import http from '@/axios/index.js';

export function oauthOidcAuthorize() {
    return http.get('/oauth/oidc/authorize')
}

export function oauthOidcLogin(code) {
    return http.post('/oauth/oidc/login',{code})
}

export function oauthLinuxDoLogin(code) {
    return oauthOidcLogin(code)
}

export function oauthBindUser(form) {
    return http.put('/oauth/bindUser', form)
}
