import { SyntheticEvent, FC, useState, useReducer } from 'react'
import { Form, Row, Col, Card } from 'react-bootstrap'
import cx from 'classnames'
import { Link, useNavigate } from 'react-router-dom'
import { InputInfo, InputInfoSet } from '../../models/InputInfo'
import SocialEvent from '../../models/SocialEvent'
import { emailValidator, noEmptyValidator } from '../../utils/RegexValidator'
import { textInputReducer } from '../../utils/InputReducer'
import FormSocialManager from '../socialLinks/SocialLinks'
import SubmitButton from '../shared/SubmitButton/SubmitButton'
import { onBasicLogin } from '../../services/UserManagementService'
import SignInRequest from '../../models/requests/SignInRequest'
import { toast } from 'react-toastify'
import { buildApiCatchMessage } from '../../utils/buildApiCatchMessage'

const SignIn: FC = () => {
  const navigate = useNavigate()

  const emailReducer = (currentState: InputInfo, action: InputInfoSet) => {
    return textInputReducer(
      currentState,
      action,
      emailValidator(action.value),
      'Your email address is invalid. Please check!'
    )
  }

  const passwordReducer = (currentState: InputInfo, action: InputInfoSet) => {
    return textInputReducer(
      currentState,
      action,
      noEmptyValidator(action.value, 10),
      'Your password address is invalid. Please check! (should be at least 8 characters)'
    )
  }

  const [email, dispatchEmail] = useReducer(emailReducer, new InputInfo())
  const [password, dispatchPassword] = useReducer(
    passwordReducer,
    new InputInfo()
  )
  const [rememberMe, setRememberMe] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  const onSubmit = (event: SyntheticEvent) => {
    event.preventDefault()
    setSubmitting(true)
    
    const request = new SignInRequest(
      email.value,
      password.value,
      rememberMe
    )
    
    onBasicLogin(request)
    .then(() => {
      toast.success('Sign in completed')
      navigate('../home')
    })
    .catch((err: Error) => toast.error(buildApiCatchMessage(err)))
    .finally(() => setSubmitting(false))
  }

  return (
    <Card className={'card-form'}>
      <Card.Header>
        <Col
          as="h5"
          sm={3}
          className="float-start"
        >
          Sign In
        </Col>
        <Col
          sm={3}
          className="float-end m-0 p-0"
        >
          <Link
            to={'../sign-up'}
            className={'primaryIconBtn'}
          >
            &nbsp;Not a member yet!
          </Link>
        </Col>
      </Card.Header>

      <Card.Body>
        <Form onSubmit={onSubmit}>
          <Form.Group
            as={Row}
            className={cx('mb-3')}
          >
            <Col>
              <Form.Label>Email:</Form.Label>
              <Form.Control
                type={'email'}
                value={email.value}
                placeholder={'your@email.com'}
                onChange={(e) =>
                  dispatchEmail({ value: e.target.value as string })
                }
                onBlur={() => dispatchEmail({ value: email.value })}
                required
                isInvalid={!email.valid}
                autoComplete="off"
                id={'login-email'}
                minLength={7}
                maxLength={20}
              />
              <Form.Control.Feedback type="invalid">
                {email.error}
              </Form.Control.Feedback>
            </Col>
          </Form.Group>

          <Form.Group
            as={Row}
            className={cx('mb-3')}
          >
            <Col>
              <Form.Label>Password:</Form.Label>
              <Form.Control
                type={'password'}
                value={password.value}
                placeholder={'**********'}
                onChange={(e) =>
                  dispatchPassword({ value: e.target.value as string })
                }
                onBlur={() => dispatchPassword({ value: password.value })}
                required
                isInvalid={!password.valid}
                autoComplete="off"
                id={'login-password'}
                minLength={10}
                maxLength={10}
              />
              <Form.Control.Feedback type="invalid">
                {password.error}
              </Form.Control.Feedback>
            </Col>
          </Form.Group>

          <Form.Group
            as={Row}
            className={'mb-3'}
          >
            <Col>
              <Form.Check.Input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className={cx('primaryCheck', 'float-start')}
                id={'singIn-remember'}
              />
              &nbsp;remember me&nbsp;
              <Link
                to={'forgot-password'}
                className={cx('primaryIconBtn', 'float-end')}
              >
                &nbsp;Forgot Password?
              </Link>
            </Col>
          </Form.Group>

          <Form.Group
            as={Row}
            className={cx('mb-3', 'text-center')}
          >
            <Col>
              <SubmitButton
                submitting={submitting}
                beforeLabel={'Sign in'}
                afterLabel={'Signing in'}
              />
            </Col>
          </Form.Group>

          <Form.Group
            as={Row}
            className={cx('mb-3', 'text-center')}
          >
            <Form.Label> Or sign in with:</Form.Label>
          </Form.Group>

          <Form.Group
            as={Row}
            className={cx('mb-3')}
          >
            <FormSocialManager socialEvent={SocialEvent.SignIn} />
          </Form.Group>
        </Form>
      </Card.Body>
    </Card>
  )
}

export default SignIn
