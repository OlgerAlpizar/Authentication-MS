import { Logger } from './configuration/logger'
import { serverPort } from './configuration/settings'
import AllowedHeadersMiddleware from './configuration/middlewares/allowedHeadersMiddleware'
import MongoConnection from './configuration/dbConnections/mongoConnection'
import YAML from 'yamljs'
import bodyParser from 'body-parser'
import cors from 'cors'
import corsOptions from './configuration/middlewares/corsMidleware'
import dotenv from 'dotenv'
import errorHandler from './configuration/middlewares/errorHandler/error-handler'
import express from 'express'
import helmet from 'helmet'
import loginRoutes from './routes/login-routes'
import morgan from 'morgan'
import swaggerUI from 'swagger-ui-express'

const app = express()
dotenv.config()

//Db
const mongo = new MongoConnection()

//middleware's
app.use(morgan('dev'))
app.use(bodyParser.json()) // to allow json capabilities
app.use(bodyParser.urlencoded({ extended: true })) // parse requests of content-type - application/x-www-form-urlencoded
app.use(helmet())
app.use(cors(corsOptions))
app.use(AllowedHeadersMiddleware)

//endpoints
app.use('/api/authentication', loginRoutes)
app.use('/', swaggerUI.serve, swaggerUI.setup(YAML.load('./swagger.yaml')))

//Global error handler
app.use(errorHandler)

//start
const port = serverPort()
app.listen(port, async () => {
  await mongo.mongooseConnectDB()
  Logger.info(`Server running on port ${port}`)
})
