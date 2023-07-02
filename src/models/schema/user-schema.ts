import { Schema, model } from 'mongoose'
import User from '../entities/user'
import uniqueValidator from 'mongoose-unique-validator'

const UserSchema = new Schema<User>(
  {
    firstName: {
      type: String,
      index: true,
      required: true,
    },
    lastName: {
      type: String,
      index: true,
      required: true,
    },
    email: {
      type: String,
      index: true,
      required: true,
      unique: true,
      match: [
        /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
        'Please use a valid email address',
      ],
    },
    password: {
      type: String,
      required: true,
      minlength: 10,
    },
    avatar: {
      type: String
    },
    receiveNotifications: {
      type: Boolean
    }
  },
  {
    timestamps: true, //auto createdAt and updatedAt columns
  }
).plugin(uniqueValidator)

export const UserSchemaModel = model<User>('User', UserSchema)
