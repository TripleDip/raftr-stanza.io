import * as NS from '../namespaces'

export default function(JXT) {
  const Utils = JXT.utils

  const Attachment = JXT.define({
    element: 'attachment',
    fields: {
      dispay_width: Utils.attribute('dispay_width'),
      display_height: Utils.attribute('display_height'),
      type: Utils.attribute('type'),
    },
    name: 'attachment',
    namespace: '',
  })

  JXT.extendMessage(Attachment)
}
