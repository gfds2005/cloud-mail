import app from '../hono/hono';
import result from "../model/result";
import oauthService from "../service/oauth-service";

app.get('/oauth/oidc/authorize', async (c) => {
	const authorizeUrl = await oauthService.authorizeUrl(c);
	return c.json(result.ok({ authorizeUrl }))
});

app.post('/oauth/oidc/login', async (c) => {
	const loginInfo = await oauthService.oidcLogin(c, await c.req.json());
	return c.json(result.ok(loginInfo))
});

app.post('/oauth/linuxDo/login', async (c) => {
	const loginInfo = await oauthService.linuxDoLogin(c, await c.req.json());
	return c.json(result.ok(loginInfo))
});

app.put('/oauth/bindUser', async (c) => {
	const loginInfo = await oauthService.bindUser(c, await c.req.json());
	return c.json(result.ok(loginInfo))
})
