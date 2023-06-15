import { FC } from 'react'
import { Modal, CloseButton } from 'react-bootstrap'
import style from './Modal.module.scss'
import cx from 'classnames'

type ModalPopProps = {
  show: boolean
  onClose: () => void
  headChild: React.ReactNode
  bodyChild: React.ReactNode
}

const ModalPop: FC<ModalPopProps> = (props: ModalPopProps) => {
  return (
    <Modal
      show={props.show}
      size="xl"
      dialogClassName="m-content"
      centered
      aria-labelledby="contained-modal-title-vcenter"
      animation
      keyboard
      onHide={props.onClose}
    >
      <Modal.Header>
        {props.headChild}

        <div className={cx('justify-content-end', style.close)}>
          <CloseButton
            className={cx('justify-content-end', style.closeIcon)}
            onClick={props.onClose}
          />
        </div>
      </Modal.Header>

      <Modal.Body>{props.bodyChild}</Modal.Body>
    </Modal>
  )
}

export default ModalPop
