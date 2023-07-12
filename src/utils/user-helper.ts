import { UserSchemaModel } from '../models/schema/user-schema'
import SignUpRequest from '../basic-auth/models/requests/sign-up-request'
import bcrypt from 'bcryptjs'

export const getUser = async (id: string, email: string) => {
  const dbUser = await UserSchemaModel.findOne({
    $or: [{ id: id }, { email: email }],
  })

  if (!dbUser) {
    throw new Error(`User ${email} does not exists`)
  }

  return dbUser
}

const checkUserPassword = async (requestPass: string, dbPass: string) => {
  const checkPass = await bcrypt.compare(requestPass, dbPass)

  if (!checkPass) {
    throw new Error('Incorrect password')
  }
}

export const checkUserCredentials = async (
  email: string,
  requestPass: string
) => {
  const dbUser = await getUser('', email)
  await checkUserPassword(requestPass, dbUser.password)

  return dbUser
}

export const saveUser = async (user: SignUpRequest) => {
  const exists = await UserSchemaModel.findOne({ email: user.email })

  if (exists) {
    throw new Error(`Email ${user.email} already exists`)
  }

  const newUser = new UserSchemaModel(user)
  newUser.password = await bcrypt.hash(newUser.password, 12)

  return await newUser.save().then((res) => {
    return res
  })
}
