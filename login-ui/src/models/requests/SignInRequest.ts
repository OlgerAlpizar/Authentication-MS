class SignInRequest {
  email: string
  password: string
  rememberMe: boolean

  constructor(
    email: string,
    password: string,
    rememberMe: boolean
  ) {
    this.email = email
    this.password = password
    this.rememberMe = rememberMe
  }

} 

export default SignInRequest