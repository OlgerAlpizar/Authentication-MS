import express from 'express'
import bodyParser from 'body-parser'
import Config from './configuration/config'
import swaggerUI from 'swagger-ui-express'
import helmet from 'helmet'
import cors from 'cors'
import corsOptions from './configuration/cors'
import MongoConnection from './configuration/mongo'
import morgan from 'morgan'
import YAML from 'yamljs'
import loginRoutes from './routes/login-routes'
import errorHandler from './configuration/errorHandler/error-handler'
import { Logger } from './configuration/logger'
import dotenv from 'dotenv'

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

//endpoints
app.use('/api/login', loginRoutes)
app.use('/', swaggerUI.serve, swaggerUI.setup(YAML.load('./swagger.yaml')))

//Global error handler
app.use(errorHandler)

//start
const port = Config.port()
app.listen(port, async() => {
  await mongo.mongooseConnectDB()
  Logger.info(`Server running on port ${port}`)
})
