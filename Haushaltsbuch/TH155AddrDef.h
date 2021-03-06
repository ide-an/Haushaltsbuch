#ifndef TH155ADDRDEF_H_INCLUDED
#define TH155ADDRDEF_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#define TH155PNAME_MAX 256

enum TH155CBMSG {
	TH155MSG_STATECHANGE,
	TH155MSG_PARAMCHANGE,
};

enum TH155STATE {
	TH155STATE_NOTFOUND,
	TH155STATE_WAITFORNETBATTLE,
	TH155STATE_NETBATTLE
};

enum TH155SCHAR {
	TH155CHAR_REIMU = 0,
	TH155CHAR_MARISA = 1,
	TH155CHAR_ICHIRIN = 2,
	TH155CHAR_HIJIRI = 3,
	TH155CHAR_FUTO = 4,
	TH155CHAR_MIKO = 5,
	TH155CHAR_NITORI = 6,
	TH155CHAR_KOISHI = 7,
	TH155CHAR_MAMIZOU = 8,
	TH155CHAR_KOKORO = 9,
	TH155CHAR_KASEN = 10,
	TH155CHAR_MOKOU = 11,
	TH155CHAR_SINMYOUMARU = 12,
	TH155CHAR_USAMI = 13,
	TH155CHAR_REISEN = 14,
	TH155CHAR_DOREMY = 15,
	TH155CHAR_TENSHI = 16,
	TH155CHAR_YUKARI = 17,
	TH155CHAR_JOUON = 18,
	TH155CHAR_MAX = 19,
};

enum TH155PARAM {
	TH155PARAM_BATTLESTATE = 0,
	TH155PARAM_ISNETCLIENT,
	TH155PARAM_P1CHAR,
	TH155PARAM_P1CHAR_SLAVE,
	TH155PARAM_P2CHAR,
	TH155PARAM_P2CHAR_SLAVE,
	TH155PARAM_P1WIN,
	TH155PARAM_P2WIN,
	TH155PARAM_MAX,
	TH155PARAM_P1NAME,
	TH155PARAM_P2NAME,
};

typedef struct {
	PCTSTR full;
	PCTSTR abbr;
} TH155CHARNAME;

int TH155AddrInit(HWND, int);
int TH155AddrFinish();
DWORD_PTR TH155AddrGetParam(int);
TH155STATE TH155AddrGetState();
const TH155CHARNAME * const TH155AddrGetCharName(int index);
int TH155AddrGetCharCount();

#ifdef __cplusplus
}
#endif

#endif /* TH155ADDRDEF_H_INCLUDED */
