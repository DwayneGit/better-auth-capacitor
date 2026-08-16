import type { AuthContext } from '@better-auth/core'
import type { EndpointContext } from 'better-call'
import { HIDE_METADATA } from 'better-auth'
import { APIError, createAuthEndpoint } from 'better-auth/api'
import * as z from 'zod'

const capacitorAuthorizationProxyOptions = {
  method: 'GET',
  query: z.object({
    authorizationURL: z.string(),
    oauthState: z.string().optional(),
  }),
  metadata: HIDE_METADATA,
} as const

async function capacitorAuthorizationProxyHandler(ctx: EndpointContext<
  '/capacitor-authorization-proxy',
  typeof capacitorAuthorizationProxyOptions,
  AuthContext
>) {
  const { oauthState } = ctx.query
  if (oauthState) {
    const oauthStateCookie = ctx.context.createAuthCookie('oauth_state', {
      maxAge: 10 * 60, // 10 minutes
    })
    ctx.setCookie(
      oauthStateCookie.name,
      oauthState,
      oauthStateCookie.attributes,
    )
    return ctx.redirect(ctx.query.authorizationURL)
  }

  const { authorizationURL } = ctx.query
  const url = new URL(authorizationURL)
  const state = url.searchParams.get('state')
  if (!state) {
    throw new APIError('BAD_REQUEST', {
      message: 'Unexpected error',
    })
  }
  const stateCookie = ctx.context.createAuthCookie('state', {
    maxAge: 5 * 60, // 5 minutes
  })
  await ctx.setSignedCookie(
    stateCookie.name,
    state,
    ctx.context.secret,
    stateCookie.attributes,
  )
  return ctx.redirect(ctx.query.authorizationURL)
}

export const capacitorAuthorizationProxy: ReturnType<typeof createAuthEndpoint<
  '/capacitor-authorization-proxy',
  typeof capacitorAuthorizationProxyOptions,
  Awaited<ReturnType<typeof capacitorAuthorizationProxyHandler>>
>> = createAuthEndpoint(
  '/capacitor-authorization-proxy',
  capacitorAuthorizationProxyOptions,
  capacitorAuthorizationProxyHandler,
)
