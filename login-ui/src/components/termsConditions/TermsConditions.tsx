import { FC } from 'react'
import ModalPop from '../shared/Modal/Modal'

type TermsConditionsProps = {
  show: boolean
  onClose: () => void
}

const TermsConditions: FC<TermsConditionsProps> = (
  props: TermsConditionsProps
) => {
  const header = <h5>Please read carefully the conditions</h5>

  const body = (
    <ul>
      <li>Your account will be monitored to generate offers</li>
      <li>Your personal information wont be shared</li>
    </ul>
  )

  return (
    <ModalPop
      show={props.show}
      onClose={props.onClose}
      headChild={header}
      bodyChild={body}
    />
  )
}

export default TermsConditions
