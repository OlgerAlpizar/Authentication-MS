import * as controller from '../controller/basic-auth-controller'
import { Router } from 'express'
import { check } from 'express-validator'
import AuthCheck from '../../configuration/middlewares/authenticationMiddleware'

const signInValidator = [
  check('email').normalizeEmail(),
  check('password').not().isEmpty(),
]

const forgotPasswordValidator = [check('email').normalizeEmail()]

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

const loginRoutes = Router()

loginRoutes.route('/sign-in').post(signInValidator, controller.signIn)

loginRoutes.route('/sign-up').post(signUpValidator, controller.signUp)

loginRoutes
  .route('/forgot-password')
  .post(forgotPasswordValidator, controller.forgotPassword)

loginRoutes.route('/refresh-session').get(controller.refreshSession)

loginRoutes.route('/sign-out').post(controller.signOut)

loginRoutes.use(AuthCheck) // follow routes will require this middleware success

loginRoutes.route('/check-auth').post(controller.checkAuthenticated)

export default loginRoutes
