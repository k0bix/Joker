#include "btc/quemsg.h"
#include "btc/net.h"

QUEMSG_ **g_pMsgQuene;
volatile int g_iQueneHead = 0, g_iQueneTail = 0;

void G_bPrintMsgQuene()
{
	DBGMSG("GET[%d] PUT[%d] FREE SPRAM=%d", g_iQueneHead, g_iQueneTail, get_free_psram_size());
}

void G_QUEMSG_Init()
{
	g_pMsgQuene = (QUEMSG_ **)ps_malloc(DEF_MSGQUENESIZE * sizeof(QUEMSG_));

	for (int i = 0; i < DEF_MSGQUENESIZE; i++)
		g_pMsgQuene[i] = NULL;
}

bool CMsg_bPut(QUEMSG_ *quemsg, uint8_t *pData, size_t dwSize, uint8_t type)
{
	quemsg->pData = (uint8_t *)ps_malloc(dwSize);
	if (quemsg->pData == NULL)
	{
		DBGMSG("[-] CMsg_bPut failed to allocate mem[%d]", dwSize);
		return false;
	}

	quemsg->type = type;
	quemsg->dwSize = dwSize;

	if (pData)
		memcpy(quemsg->pData, pData, dwSize);
	else
		quemsg->pData = NULL;

	return true;
}

bool G_bPutMsgQuene(uint8_t *pData, size_t dwMsgSize, uint8_t type)
{
	uint32_t dwMagic = 0xCCCCCCCC;
	if (dwMsgSize == 0)
	{
		assert(pData == NULL);
		dwMsgSize = 4;
		pData = (uint8_t *)&dwMagic;
	}
	
	if (g_iQueneTail >= DEF_MSGQUENESIZE)
		g_iQueneTail = 0;
	
	if (g_pMsgQuene[g_iQueneTail] != NULL)
	{
		RELEASE_PTR(g_pMsgQuene[g_iQueneTail]->pData)
		RELEASE_PTR(g_pMsgQuene[g_iQueneTail])
	}

	g_pMsgQuene[g_iQueneTail] = (QUEMSG_ *)ps_malloc(sizeof(QUEMSG_));

	if (g_pMsgQuene[g_iQueneTail] == NULL)
		return false;

	if (CMsg_bPut(g_pMsgQuene[g_iQueneTail], pData, dwMsgSize, type) == false)
	{
		RELEASE_PTR(g_pMsgQuene[g_iQueneTail])
		return false;
	}

	g_iQueneTail++;

	return true;
}

uint8_t *CMsg_Get(QUEMSG_ *quemsg, size_t *pSize, uint8_t *type)
{
	uint8_t *pbuffer = ps_malloc(quemsg->dwSize);
	if (pbuffer)
	{
		memcpy(pbuffer, quemsg->pData, quemsg->dwSize);
	}
	*pSize = quemsg->dwSize;
	*type = quemsg->type;

	return pbuffer;
}

uint8_t *G_bGetMsgQuene(size_t *pMsgSize, uint8_t *type)
{
	if (g_pMsgQuene[g_iQueneHead] == NULL)
		return NULL;

	if ((g_pMsgQuene[g_iQueneHead]->dwSize == 0))
		return NULL;

	uint8_t *pbuffer = CMsg_Get(g_pMsgQuene[g_iQueneHead], pMsgSize, type);

	if (pbuffer == NULL)
		return NULL;
	RELEASE_PTR(g_pMsgQuene[g_iQueneHead]->pData)

	RELEASE_PTR(g_pMsgQuene[g_iQueneHead])

	g_iQueneHead++;
	
	if (g_iQueneHead >= DEF_MSGQUENESIZE)
		g_iQueneHead = 0;

	return pbuffer;
}