#if !defined(AFX_MSG_H__QUEMSG___INCLUDED_)
#define AFX_MSG_H__QUEMSG___INCLUDED_

#include <Arduino.h>

#define DEF_MSGQUENESIZE 50

typedef struct QUEMSG_
{
    uint8_t  type;
	uint8_t *pData;
	uint32_t dwSize;

} QUEMSG_;

#endif 
