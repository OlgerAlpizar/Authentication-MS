import { signAccessToken } from '../../../utils/jwt-helper'
import User from '../../../models/entities/user'

interface AuthResponse {
  accessToken: string
  firstName: string
  lastName: string
  avatar: string
  email: string
}

export const getAuthTokenResponse = (user: User) => {
  return {
    accessToken: signAccessToken(user),
    firstName: user.firstName,
    lastName: user.lastName,
    avatar: user.avatar,
    email: user.email,
  }
}

export default AuthResponse
