import Config from '../configuration/config'
import CreateAccount from '../models/requests/CreateAccountRequest'
import SignInRequest from '../models/requests/SignInRequest'
import SocialLink from '../models/SocialLink'
import axios from 'axios'

export const authApi = axios.create({ baseURL: Config.loginApi() })

export const onLoginSocialLink = async (link: SocialLink): Promise<unknown> => {
  throw `Social login not implemented yet ${link}`
}

export const onRegisterSocialLink = async (
  link: SocialLink
): Promise<unknown> => {
  throw `Social register not implemented yet ${link}`
}

export const onBasicLogin = async (request: SignInRequest): Promise<unknown> => {
  return authApi.post('/sign-in', request).then((res) => res.data)
}

export const onBasicRegister = async (
  request: CreateAccount
): Promise<boolean> => {
  return authApi.post('/sign-up', request).then((res) => res.data)
}
