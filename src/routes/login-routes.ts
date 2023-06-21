import * as controller from '../controller/login-controller'
import { Router } from 'express'
import { check } from 'express-validator'

const signInValidator = [
  check('email').normalizeEmail(),
  check('password').not().isEmpty(),
]

const signUpValidator = [
  check('lastName').not().isEmpty(),
  check('firstName').not().isEmpty(),
  check('email').normalizeEmail(),
  check('password').isStrongPassword({
    minLength: 10,
    minNumbers: 3,
    minLowercase: 3,
    minUppercase: 2,
    minSymbols: 2,
  }),
]

const signOutValidator = [check('email').normalizeEmail()]

const loginRoutes = Router()

loginRoutes.route('/sign-in').post(signInValidator, controller.signIn)

loginRoutes.route('/sign-up').post(signUpValidator, controller.signUp)

loginRoutes.route('/sign-out').post(signOutValidator, controller.signOut)

export default loginRoutes
