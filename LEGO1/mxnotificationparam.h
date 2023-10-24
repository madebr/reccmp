#ifndef MXNOTIFICATIONPARAM_H
#define MXNOTIFICATIONPARAM_H

#include "compat.h"
#include "mxparam.h"
#include "mxtypes.h"

class MxCore;

enum MxParamType
{
  PARAM_NONE = 0,
  PAINT = 1, // 100dc210:100d8350
  MXSTREAMER_UNKNOWN = 2, // 100d8358:100d8350
  TYPE4 = 4, // 100dc208:100d8350
  MXPRESENTER_NOTIFICATION = 5,
  MXSTREAMER_DELETE_NOTIFY = 6, // 100dc760
  APP_MESSAGE = 7, // 100d6aa0
  MOUSE_RELEASE = 8, // 100d6aa0
  MOUSE_PRESS = 9, // 100d6aa0
  MOUSE_MOVE = 10, // 100d6aa0
  TYPE11 = 11, // 100d6aa0
  PARAM_TIMER = 15, // 100d6aa0
  TYPE17 = 17,
  TYPE18 = 18, // 100d7e80
  TYPE19 = 19, // 100d6230
  TYPE20 = 20,
  TYPE21 = 21,
  TYPE22 = 22,
  TYPE23 = 23,
  MXTRANSITIONMANAGER_TRANSITIONENDED = 24
};

// VTABLE 0x100d56e0
class MxNotificationParam : public MxParam
{
public:
  inline MxNotificationParam(MxParamType p_type, MxCore *p_sender) : MxParam(), m_type(p_type), m_sender(p_sender){}

  virtual ~MxNotificationParam() override {} // vtable+0x0 (scalar deleting destructor)
  virtual MxNotificationParam *Clone(); // vtable+0x4

  inline MxParamType GetType() const { return m_type; }
  inline MxCore *GetSender() const { return m_sender; }

protected:
  MxParamType m_type; // 0x4
  MxCore *m_sender; // 0x8
};

#endif // MXNOTIFICATIONPARAM_H