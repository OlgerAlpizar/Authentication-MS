import { FC } from 'react'
import { BsFacebook, BsGoogle } from 'react-icons/bs'
import SocialEvent from '../../models/SocialEvent'
import SocialLink from '../../models/SocialLink'
import ButtonIcon from '../shared/IconButton/IconButton'
import {
  onLoginSocialLink,
  onRegisterSocialLink,
} from '../../services/UserManagementService'
import { toast } from 'react-toastify'
import { Col } from 'react-bootstrap'

type SocialLinksProps = {
  socialEvent: SocialEvent
}

const SocialLinks: FC<SocialLinksProps> = (props: SocialLinksProps) => {
  const onSocialLinkClick = (link: SocialLink) => {
    switch (props.socialEvent) {
      case SocialEvent.SignIn:
        onLoginSocialLink(link)
          .then((res) => console.log('success', res))
          .catch((err) => toast.error(err))
        break
      case SocialEvent.Register:
        onRegisterSocialLink(link)
          .then((res) => console.log('success', res))
          .catch((err) => toast.error(err))
        break
    }
  }

  return (
    <>
      <Col sm={6}>
        <ButtonIcon
          type="button"
          label=""
          onClick={(_) => onSocialLinkClick(SocialLink.FACEBOOK)}
        >
          <BsFacebook
            className={'primaryIconBtn'}
            title="Facebook"
            size={30}
          />
        </ButtonIcon>
      </Col>

      <Col sm={6}>
        <ButtonIcon
          type="button"
          label=""
          onClick={(_) => onSocialLinkClick(SocialLink.GOOGLE)}
        >
          <BsGoogle
            className={'primaryIconBtn'}
            title="Gmail"
            size={30}
          />
        </ButtonIcon>
      </Col>
    </>
  )
}

export default SocialLinks
