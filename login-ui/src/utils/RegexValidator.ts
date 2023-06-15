export const emailValidator = (email: string) =>
  /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(email) &&
  maxCharacters(email, 20)
  
export const noEmptyValidator = (text: string, length: number) =>
  maxCharacters(text, length)

export const noEmptyOrSpecialValidator = (text: string) =>
  /^[A-Za-z0-9]*$/.test(text) && maxCharacters(text, 20)

export const maxCharacters = (text: string, length: number) =>
  new RegExp(`^.{1,${length}}$`).test(text)

export const passwordValidator = (password: string) =>
  /^(?=.*[A-Z].*[A-Z])(?=.*[!@#$&*])(?=.*[0-9].*[0-9])(?=.*[a-z].*[a-z].*[a-z]).{10}$/.test(
    password
  )
export const conformPasswordValidator = (
  password: string,
  confirmation: string
) => passwordValidator(password) && password === confirmation
