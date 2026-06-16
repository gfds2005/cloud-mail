import BizError from "../error/biz-error";
import orm from "../entity/orm";
import {oauth} from "../entity/oauth";
import { eq, inArray } from 'drizzle-orm';
import userService from "./user-service";
import loginService from "./login-service";
import cryptoUtils from "../utils/crypto-utils";

const DISCOVERY_TTL = 1000 * 60 * 10;
const discoveryCache = new Map();

function normalizeIssuer(issuer) {
	return issuer?.replace(/\/+$/, '') || '';
}

function envValue(c, key, fallbackKey) {
	return c.env[key] || c.env[key.toUpperCase()] || c.env[fallbackKey] || c.env[fallbackKey?.toUpperCase?.()];
}

function boolEnv(value) {
	return value === true || value === 'true';
}

function getOidcConfig(c) {
	const issuer = normalizeIssuer(envValue(c, 'oidc_issuer', 'linuxdo_issuer') || 'https://connect.linux.do');
	const scopes = envValue(c, 'oidc_scopes', 'linuxdo_scopes') || 'openid profile email';

	return {
		issuer,
		clientId: envValue(c, 'oidc_client_id', 'linuxdo_client_id'),
		clientSecret: envValue(c, 'oidc_client_secret', 'linuxdo_client_secret'),
		callbackUrl: envValue(c, 'oidc_callback_url', 'linuxdo_callback_url'),
		switch: boolEnv(envValue(c, 'oidc_switch', 'linuxdo_switch')),
		scopes,
		providerName: envValue(c, 'oidc_provider_name', 'linuxdo_provider_name') || 'OIDC'
	}
}

function assertOidcEnabled(config) {
	if (!config.switch) {
		throw new BizError('OIDC登录未启用')
	}
	if (!config.issuer || !config.clientId || !config.clientSecret || !config.callbackUrl) {
		throw new BizError('OIDC配置不完整')
	}
}

function mapUserInfo(config, userInfo) {
	const sub = userInfo.sub || userInfo.id;
	if (!sub) {
		throw new BizError('OIDC用户信息缺少sub')
	}

	const username = userInfo.preferred_username || userInfo.email || String(sub);
	const name = userInfo.name || username;

	return {
		oauthUserId: `${config.issuer}:${sub}`,
		username,
		name,
		avatar: userInfo.picture || userInfo.avatar_url || '',
		active: 0,
		trustLevel: userInfo.trust_level || 0,
		silenced: 0
	}
}

const oauthService = {

	getOidcConfig,

	async bindUser(c, params) {

		const { email, oauthUserId, code } = params;

		const oauthRow = await this.getById(c, oauthUserId);

		let userRow = await userService.selectByIdIncludeDel(c, oauthRow.userId);

		if (userRow) {
			throw new BizError('用户已绑定有邮箱')
		}

		await loginService.register(c, { email, password: cryptoUtils.genRandomPwd(), code }, true);

		userRow = await userService.selectByEmail(c, email);

		orm(c).update(oauth).set({ userId: userRow.userId }).where(eq(oauth.oauthUserId, oauthUserId)).run();
		const jwtToken = await loginService.login(c, { email, password: null }, true);

		return { userInfo: oauthRow, token: jwtToken}
	},

	async discover(c) {
		const config = getOidcConfig(c);
		assertOidcEnabled(config);

		const cached = discoveryCache.get(config.issuer);
		if (cached && cached.expiresAt > Date.now()) {
			return cached.discovery
		}

		const discoveryRes = await fetch(`${config.issuer}/.well-known/openid-configuration`);
		if (!discoveryRes.ok) {
			throw new BizError(discoveryRes.statusText)
		}

		const discovery = await discoveryRes.json();
		if (!discovery.authorization_endpoint || !discovery.token_endpoint || !discovery.userinfo_endpoint) {
			throw new BizError('OIDC发现文档缺少必要端点')
		}
		if (discovery.issuer && normalizeIssuer(discovery.issuer) !== config.issuer) {
			throw new BizError('OIDC Issuer不匹配')
		}

		discoveryCache.set(config.issuer, {
			discovery,
			expiresAt: Date.now() + DISCOVERY_TTL
		});

		return discovery;
	},

	async authorizeUrl(c) {
		const config = getOidcConfig(c);
		assertOidcEnabled(config);
		const discovery = await this.discover(c);
		const url = new URL(discovery.authorization_endpoint);
		url.searchParams.set('client_id', config.clientId);
		url.searchParams.set('redirect_uri', config.callbackUrl);
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('scope', config.scopes);
		return url.toString();
	},

	async linuxDoLogin(c, params) {
		return this.oidcLogin(c, params)
	},

	async oidcLogin(c, params) {

		const { code } = params;
		const config = getOidcConfig(c);
		assertOidcEnabled(config);
		const discovery = await this.discover(c);

		let token = '';
		let userInfo = {}

		const reqParams = new URLSearchParams()
		reqParams.append('client_id', config.clientId)
		reqParams.append('client_secret', config.clientSecret)
		reqParams.append('code', code)
		reqParams.append('redirect_uri', config.callbackUrl)
		reqParams.append('grant_type', 'authorization_code')

		const tokenRes = await fetch(discovery.token_endpoint, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: reqParams.toString()
		})

		if (!tokenRes.ok) {
			throw new BizError(tokenRes.statusText)
		}

		token = await tokenRes.json()

		const userRes = await fetch(discovery.userinfo_endpoint, {
			headers: {
				Authorization: 'Bearer ' + token.access_token
			}
		});

		if (!userRes.ok) {
			throw new BizError(userRes.statusText)
		}

		const rawUserInfo = await userRes.json();
		userInfo = mapUserInfo(config, rawUserInfo);

		const  oauthRow = await this.saveUser(c, userInfo, [rawUserInfo.sub, rawUserInfo.id].filter(Boolean).map(String));
		const userRow = await userService.selectByIdIncludeDel(c, oauthRow.userId);

		if (!userRow) {
			return { userInfo: oauthRow, token: null }
		}

		const JwtToken = await loginService.login(c, { email: userRow.email, password: null }, true);
		return { userInfo: oauthRow, token: JwtToken }
	},

	async saveUser(c, userInfo, fallbackIds = []) {

		let userInfoRow = await this.getById(c, userInfo.oauthUserId);
		for (const fallbackId of fallbackIds) {
			if (!userInfoRow && fallbackId !== userInfo.oauthUserId) {
				userInfoRow = await this.getById(c, fallbackId);
			}
		}

		if (!userInfoRow) {
			return await orm(c).insert(oauth).values(userInfo).returning().get();
		} else {
			return await orm(c).update(oauth).set(userInfo).where(eq(oauth.oauthId, userInfoRow.oauthId)).returning().get();
		}

	},

	async getById(c, oauthUserId) {
		return await orm(c).select().from(oauth).where(eq(oauth.oauthUserId, oauthUserId)).get();
	},

	async deleteByUserId(c, userId) {
		await this.deleteByUserIds(c, [userId]);
	},

	async deleteByUserIds(c, userIds) {
		await orm(c).delete(oauth).where(inArray(oauth.userId, userIds)).run();
	},

	//定时任务凌晨清除未绑定邮箱的oauth用户
	async clearNoBindOathUser(c) {
		await orm(c).delete(oauth).where(eq(oauth.userId, 0)).run();
	},

}

export default  oauthService
