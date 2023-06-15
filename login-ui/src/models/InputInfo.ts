export class InputInfo {
  valid: boolean
  value: string
  error: string

  constructor(valid: boolean = true, value: string = '', error: string = '') {
    this.valid = valid
    this.value = value
    this.error = error
  }
}

export type InputInfoSet = {
  value: string
}
