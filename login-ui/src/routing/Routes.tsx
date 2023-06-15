import { createRoutesFromElements, Outlet, Route } from 'react-router-dom'
import Home from '../components/home/Home'
import ForgotPassword from '../components/forgotPassword/ForgotPassword'
import SignIn from '../components/signIn/SignIn'
import SignUp from '../components/signUp/SignUp'
import { FC } from 'react'
import NewAccount from '../components/newAccount/NewAccount'

const RouteNotDefined: FC = () => {
  return <>That route does not exist</>
}

export const routeDefinitions = createRoutesFromElements(
  <Route
    path="/"
    element={<Outlet />}
    errorElement={<RouteNotDefined />}
  >
    <Route
      path="sign-in"
      element={<SignIn />}
    />
    <Route
      path="sign-up"
      element={<SignUp />}
    />
    <Route
      path="forgot-password"
      element={<ForgotPassword />}
    />
    <Route
      path="home"
      element={<Home />}
    />
    <Route
      path="newAccount"
      element={<NewAccount />}
    />
  </Route>
)
