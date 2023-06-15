class CreateAccountRequest {
  firstName: string
  lastName: string
  email: string
  password: string
  allowNotifications: boolean

  constructor(
    firstName: string,
    lastName: string,
    email: string,
    password: string,
    allowNotifications: boolean
  ) {
    this.firstName = firstName
    this.lastName = lastName
    this.email = email
    this.password = password
    this.allowNotifications = allowNotifications
  }
}

export default CreateAccountRequest
