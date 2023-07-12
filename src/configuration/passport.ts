import { googleClientId, googleClientSecret } from './settings'
import GoogleStrategy from 'passport-google-oauth20'
import passport from 'passport'

passport.use(
  new GoogleStrategy.Strategy(
    {
      clientID: googleClientId(),
      clientSecret: googleClientSecret(),
      callbackURL: '/auth/google/callback',
    },
    function (_accessToken, _refreshToken, profile, done) {
      done(null, profile)
    }
  )
)

passport.serializeUser((user: Express.User, done) => {
  done(null, user)
})

passport.deserializeUser((user: Express.User, done) => {
  done(null, user)
})
