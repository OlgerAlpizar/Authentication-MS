import { CookieOptions } from 'express'
import { expirationRefreshToken } from '../configuration/settings'

// Cookie options
const generateCookieOptions = (
  expireSecs: number,
  httpOnly?: boolean
): CookieOptions => {
  return {
    sameSite: 'none', //cross sites
    secure: true, // required be same site cross
    httpOnly: httpOnly ?? false, //use just an http
    expires: new Date(Date.now() + expireSecs * 1000),
    maxAge: expireSecs * 1000,
    path: '/',
  }
}

export const deleteCookieOptions = (): CookieOptions => {
  return {
    sameSite: 'none',
    secure: true,
  }
}

export const signedCookieOptions = (): CookieOptions => {
  return generateCookieOptions(expirationRefreshToken())
}

export const refreshTokenCookieOptions = (): CookieOptions => {
  return generateCookieOptions(expirationRefreshToken(), true)
}
