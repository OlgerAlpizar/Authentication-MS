import { FC } from 'react'
import { RouterProvider, createBrowserRouter } from 'react-router-dom'
import { routeDefinitions } from './routing/Routes'
import { toast, ToastContainer } from 'react-toastify'
import { Container, Row, Col } from 'react-bootstrap'
import cx from 'classnames'

type AppProps = {
  baseUrl: string
}

const App: FC<AppProps> = (_props: AppProps) => {
  return (
    <Container className={cx('justify-content-center')}>
      <Row className={cx('justify-content-center')}>
        <Col>
          <RouterProvider router={createBrowserRouter(routeDefinitions)} />

          <ToastContainer
            autoClose={5000}
            position={toast.POSITION.BOTTOM_RIGHT}
            pauseOnFocusLoss={false}
            newestOnTop={true}
            limit={5}
          />
        </Col>
      </Row>
    </Container>
  )
}
export default App
