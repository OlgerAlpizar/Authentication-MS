import { InputInfo, InputInfoSet } from '../models/InputInfo'

export const textInputReducer = (
  currentState: InputInfo,
  action: InputInfoSet,
  isValid: boolean,
  errorNote: string
) => {
  return {
    ...currentState,
    valid: isValid,
    value: action.value,
    error: isValid ? '' : errorNote,
  }
}
