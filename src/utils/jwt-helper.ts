import {
  expirationAccessToken,
  expirationRefreshToken,
  jwtAccessTokenSecret,
  jwtRefreshTokenSecret,
} from '../configuration/settings'
import User from '../models/entities/user'
import jwt, { VerifyErrors } from 'jsonwebtoken'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const signToken = (payload: any, secret: string, expireInSeconds: number) => {
  // allow any here because payload could be any kind of object
  return jwt.sign(payload, secret, {
    expiresIn: expireInSeconds,
  })
}

export const signAccessToken = (user: User) => {
  const payload = {
    id: user.id,
    email: user.email,
  }

  return signToken(payload, jwtAccessTokenSecret(), expirationAccessToken())
}

export const signSignedToken = () => {
  const payload = {
    date: new Date(),
  }

  return signToken(payload, jwtRefreshTokenSecret(), expirationRefreshToken())
}

export const signRefreshToken = (user: User) => {
  const payload = {
    id: user.id,
    email: user.email,
  }

  return signToken(payload, jwtRefreshTokenSecret(), expirationRefreshToken())
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const getTokenDecode = (token: string, secret: string): any => {
  if (!token) {
    throw new Error('No token present')
  }
  return jwt.verify(
    token,
    secret,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (error: VerifyErrors | null, decoded: any) => {
      //enable any for decoded
      if (error) {
        throw error
      }
      return decoded
    }
  )
}
