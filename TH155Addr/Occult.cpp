#include <Windows.h>
#include <ImageHlp.h>
#include <shlwapi.h>
#include <stdio.h>

static const void *memmem(const void *haystack, size_t haystacklen,
	const void *needle, size_t needlelen)
{
	if (needlelen <= haystacklen)
		for (const char *p = static_cast<const char*>(haystack);
		(p + needlelen) <= (static_cast<const char *>(haystack) + haystacklen);
			p++)
			if (memcmp(p, needle, needlelen) == 0)
				return p;

	return nullptr;
}

static LPCVOID findNearCall(LPCVOID haystack, size_t haystack_len, LPCVOID callee) {
	LPCBYTE begin = static_cast<LPCBYTE>(haystack);
	LPCBYTE const last_possible = begin + haystack_len - sizeof(callee) - 1;
	ptrdiff_t tail = static_cast<LPCBYTE>(callee) - begin - 5;

	for (; begin <= last_possible; begin++, tail--) {
		if (*begin == 0xE8 && !memcmp(begin + 1, &tail, sizeof tail))
			return begin;
	}
	return nullptr;
}

static PIMAGE_SECTION_HEADER GetSection(LOADED_IMAGE &img, PCSTR sectionName)
{
	int cmplen = ::lstrlenA(sectionName);
	if (cmplen > 0 && cmplen <= sizeof(IMAGE_SECTION_HEADER::Name)) {
		for (ULONG i = 0; i < img.NumberOfSections; ++i) {
			if (::StrCmpNA(static_cast<PSTR>(static_cast<PVOID>(img.Sections[i].Name)), sectionName, cmplen) == 0) {
				return &img.Sections[i];
			}
		}
	}
	return nullptr;
}

static bool pseudoMapAndLoad(PLOADED_IMAGE img)
{
	if (img == nullptr) return false;

	HMODULE mainMod = ::GetModuleHandle(nullptr);
	if (mainMod == nullptr) return false;
	PIMAGE_NT_HEADERS nthdr = ImageNtHeader(mainMod); // https://msdn.microsoft.com/ja-jp/library/cc428957.aspx
	if (nthdr == nullptr) return false; // https://msdn.microsoft.com/ja-jp/library/windows/desktop/ms680336(v=vs.85).aspx

	RtlZeroMemory(img, sizeof(img));
	img->MappedAddress = reinterpret_cast<PUCHAR>(mainMod);
	img->FileHeader = nthdr;
	img->NumberOfSections = nthdr ->FileHeader.NumberOfSections;
	img->Sections = IMAGE_FIRST_SECTION(nthdr); // http://tech.blog.aerie.jp/entry/2015/12/27/140649

	return true;
}

extern "C" DWORD_PTR GetCoreBase()
{
	/*
	����Ă邱�Ƃ�傴���ςɁB
	1. SQVM��RTTI(TypeDescriptor)��������
	2. TypeDescriptor�ARTTICompleteObjectLocator�ƒH���āASQVM��vtable�̐擪��������
	3. vtable�̃A�h���X��������R�[�h��SQVM�̃R���X�g���N�^�Ȃ͂��A�Ƃ������Ƃ�SQVM�̃R���X�g���N�^��������
	4. SQVM�̃R���X�g���N�^�Asq_open�Amysq_create�ƌĂяo������H��
	5. mysq_create�̌Ăяo�����ŁA�߂�l���O���[�o���ϐ��Ɋi�[����R�[�h��T���A���̃O���[�o���ϐ��̃A�h���X����肷��B
	*/
	LOADED_IMAGE img; // https://msdn.microsoft.com/ja-jp/library/windows/desktop/ms680349(v=vs.85).aspx
	if (!::pseudoMapAndLoad(&img)) {
		return 0;
	}
	// �����܂ł�Sections�̐擪��Sections�̌��͕������Ă���B
	PIMAGE_SECTION_HEADER const text = GetSection(img, ".text");
	PIMAGE_SECTION_HEADER const rdata = GetSection(img, ".rdata");
	PIMAGE_SECTION_HEADER const data = GetSection(img, ".data");
	if (!text || !rdata || !data) {
		return 0;
	}
	PVOID const textBase = ImageRvaToVa(img.FileHeader, img.MappedAddress, text->VirtualAddress, nullptr); // https://msdn.microsoft.com/ja-jp/library/windows/desktop/ms680218(v=vs.85).aspx
	PVOID const dataBase = ImageRvaToVa(img.FileHeader, img.MappedAddress, data->VirtualAddress, nullptr); // data->VirtualAddress�̒l��ImageBase����̑��Βl�Ƃ������ƂŎ��ۂɂ�RVA�B�����VA�ɕϊ�����
	PVOID const rdataBase = ImageRvaToVa(img.FileHeader, img.MappedAddress, rdata->VirtualAddress, nullptr);
	// �P��VirtualSize�ł��ǂ����������ASectionAlignment���l�����ė]�v�ɒǉ����Ă���B
	// https://twitter.com/sakra_yukikaze/status/957634400660865024
	// https://twitter.com/sakra_yukikaze/status/957635347353034752
	DWORD const textSize = (text->Misc.VirtualSize + img.FileHeader->OptionalHeader.SectionAlignment - 1) & ~(img.FileHeader->OptionalHeader.SectionAlignment - 1);
	DWORD const dataSize = (data->Misc.VirtualSize + img.FileHeader->OptionalHeader.SectionAlignment - 1) & ~(img.FileHeader->OptionalHeader.SectionAlignment - 1);
	DWORD const rdataSize = (rdata->Misc.VirtualSize + img.FileHeader->OptionalHeader.SectionAlignment - 1) & ~(img.FileHeader->OptionalHeader.SectionAlignment - 1);

	// rdata����Ȃ���data�Ȃ̂��H
	LPCBYTE const sqvmRttiStr = static_cast<LPCBYTE>(memmem(dataBase, dataSize, ".?AUSQVM@@", 10)); // data�̈悩��RTTI��T��
	// Reversing C++ pp.14 ��TypeDescriptor�������Ă���B
	// http://www.openrce.org/articles/full_view/21
	// ���L��name��������B
	/*
	struct TypeDescriptor {
		// vtable of type_info class
		const void * pVFTable;
		// used to keep the demangled name returned by type_info::name()
		void* spare;
		// mangled type name, e.g. ".H" = "int", ".?AUA@@" = "struct A", ".?AVA@@" = "class A"
		char name[0];
	};
	*/
	if (!sqvmRttiStr) {
		return 0;
	}
	// sqvmRttiStr - 8��TypeDescriptor�̐擪�B�A�h���X�ϊ��I�Ȃ��̂��Ǝv�����A���̕ӂ̏ڂ����v�Z���킩��Ȃ��B
	DWORD_PTR const sqvmRttiStrRef = sqvmRttiStr - 8 - static_cast<LPBYTE>(dataBase) + img.FileHeader->OptionalHeader.ImageBase + data->VirtualAddress;

	LPCBYTE const sqvmRtti = static_cast<LPCBYTE>(memmem(rdataBase, rdataSize, &sqvmRttiStrRef, sizeof DWORD_PTR));
	// rdata����TypeDescriptor���Q�Ƃ��镔����T���B�����Ō������̂͂����炭RTTICompleteObjectLocator.pTypeDescriptor
	// http://www.openrce.org/articles/full_view/23
	/*
	struct RTTICompleteObjectLocator
	{
		DWORD signature; //always zero ?
		DWORD offset;    //offset of this vtable in the complete class
		DWORD cdOffset;  //constructor displacement offset
		struct TypeDescriptor* pTypeDescriptor; //TypeDescriptor of the complete class
		struct RTTIClassHierarchyDescriptor* pClassDescriptor; //describes inheritance hierarchy
	};
	*/
	if (!sqvmRtti) {
		return 0;
	}
	// sqvmRtti - 12��RTTICompleteObjectLocator�̐擪�B���̕ӂ̏ڂ����v�Z���킩��Ȃ��B
	DWORD_PTR const sqvmRttiRef = sqvmRtti - 12 - static_cast<LPBYTE>(rdataBase) + img.FileHeader->OptionalHeader.ImageBase + rdata->VirtualAddress;

	LPCBYTE const sqvmVtblRtti = static_cast<LPCBYTE>(memmem(rdataBase, rdataSize, &sqvmRttiRef, 4));
	// ������vtable��������Bvtable�́u1�O�v��RTTICompleteObjectLocator�ւ̃|�C���^�������Ă�B
	// http://www.openrce.org/articles/img/igor2_rtti1.gif ����� Reversing C++ pp.13
	if (!sqvmVtblRtti) {
		return 0;
	}
	// vtable�̐擪�A�h���X�����߂�B
	DWORD_PTR const sqvmVtblRef = sqvmVtblRtti + 4 - static_cast<LPBYTE>(rdataBase) + img.FileHeader->OptionalHeader.ImageBase + rdata->VirtualAddress;

	LPCBYTE const sqvmCtorHint = static_cast<LPCBYTE>(memmem(textBase, textSize, &sqvmVtblRef, sizeof DWORD_PTR));
	// vtable���Q�Ƃ���R�[�h��T���B�R���X�g���N�^�̃R�[�h�f�Ђ�������͂��B
	// �߈ˉ�ver 1.03�̏ꍇ�A0x58c42a
	if (!sqvmCtorHint) {
		return 0;
	}

	// �R���X�g���N�^�̐擪�A�h���X�����߂�BsqvmCtorHead�͊֐��̃v�����[�O�B�ȉ��ɑΉ�����@�B��B
	// .text:0058C3F0                 push    ebp
	// .text:0058C3F1                 mov     ebp, esp
	// .text:0058C3F3                 push    0FFFFFFFFh
	BYTE const sqvmCtorHead[] = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF };
	LPCBYTE const sqvmCtor = static_cast<LPCBYTE>(memmem(sqvmCtorHint - 0x40, 0x40, sqvmCtorHead, sizeof sqvmCtorHead));
	if (!sqvmCtor) {
		return 0;
	}

	LPCBYTE sq_openHintBase = static_cast<LPCBYTE>(textBase);
	DWORD sq_openHintSize = textSize;
	for (;;) {
		// SQVM�̃R���X�g���N�^�̌Ăяo������������BSquirrel�̃R�[�h��SQVM�̃R���X�g���N�^���ĂԂ̂�sq_open()��sq_newthread()�B
		// �߈ˉ؂ł�sq_open()���Ă�ł���Ɖ���B
		LPCBYTE const sq_openHint = static_cast<LPCBYTE>(findNearCall(sq_openHintBase, sq_openHintSize, sqvmCtor));
		if (!sq_openHint) {
			return 0;
		}
		sq_openHintSize -= sq_openHint - sq_openHintBase;
		sq_openHintBase = sq_openHint + 1;

		// sq_open()�̐擪�A�h���X�����߂�B�������֐��̃v�����[�O���g���Č�������B
		BYTE const sq_openHead[] = { 0x55, 0x8B, 0xEC }; // push ebp; mov ebp, esp
		LPCBYTE const sq_open = static_cast<LPCBYTE>(memmem(sq_openHint - 0x48, 0x48, sq_openHead, sizeof sq_openHead));
		if (!sq_open) {
			continue;
		}

		LPCBYTE mysq_createHintbase = static_cast<LPCBYTE>(textBase);
		DWORD mysq_createHintSize = textSize;
		for (;;) {
			// sq_open()�̌Ăяo������������B���̕ӂ̓X�N���v�g�G���W���̊O�A�����t���Ǝ��R�[�h�Ǝv����B
			LPCBYTE const mysq_createHint = static_cast<LPCBYTE>(findNearCall(mysq_createHintbase, mysq_createHintSize, sq_open));
			if (!mysq_createHint) {
				break;
			}
			/*
				; �߈ˉ�ver 1.03�̏ꍇ
				.text:00424690 sub_424690      proc near               ; CODE XREF: sub_40D530+17Cp
				.text:00424690                                         ; sub_455E10+29p
				.text:00424690                 push    esi
				.text:00424691                 push    400h
				.text:00424696                 call    sub_5840B0      ;; ������sq_open()�̌Ăяo��
				.text:0042469B                 mov     esi, eax        ;; �߂�l��SQVM���Ԃ��Ă���B
				; ���̊֐��͂��̌�esi�����낢��Ȋ֐��ɓn������ASQVM��߂�l�Ƃ��ĕԂ��B
				; �Ȃ̂ł��̊֐��̌Ăяo������T���B
				; sub_424690 == mysq_create
			*/
			mysq_createHintSize -= mysq_createHint - mysq_createHintbase;
			mysq_createHintbase = mysq_createHint + 1;

			// mysq_create�̌Ăяo������T���B�v�����[�O��T���̂ł͂Ȃ��A���̃A�h���X��Near Call�ŌĂ΂�Ă��邩��mysq_create()�̐擪���ǂ������肷��B
			LPCBYTE mysq_initHint;
			int mysq_initHintFindOffset = 1;
			for (; mysq_initHintFindOffset <= 0x30; ++mysq_initHintFindOffset) {
				LPCBYTE const mysq_create = mysq_createHint - mysq_initHintFindOffset; // push reg32; push imm32(0x400)
				mysq_initHint = static_cast<LPCBYTE>(findNearCall(textBase, textSize, mysq_create));
				if (mysq_initHint) {
					// mysq_initHint��mysq_create()�̌Ăяo����
					break;
				}
			}
			// mysq_create()�̖߂�l�́Aesi���o�R���āA�Ƃ���O���[�o���ϐ��Ɋi�[�����B�Ƃ������Ƃ�mysq_create()�̌Ăяo���ȍ~�ł����������R�[�h��T���B
			// .text : 0040D6AC                 call    sub_424690 ; mysq_create()�̌Ăяo��
			// .text : 0040D6B1                 mov     esi, eax ; �߂�l��esi��
			// .text : 0040D6B3                 mov     dword_8DACC0, 0
			// .text : 0040D6BD                 lea     eax, [ebp + var_74]
			// .text : 0040D6C0                 mov     dword_XXXXXXXX, esi ; ����������̉ӏ��B�@�B�ꂾ�Ɓu89 35 XX XX XX XX�v�B
			if (mysq_initHintFindOffset <= 0x20) {
				BYTE const movToGlobalVarHintOps[] = { 0x89, 0x35 }; // mov ds:[imm32], esi
				LPCBYTE const movToGlobalVarHint = static_cast<LPCBYTE>(memmem(mysq_initHint + 5, 0x20, movToGlobalVarHintOps, sizeof movToGlobalVarHintOps));
				if (!movToGlobalVarHint) {
					continue;
				}
				// �O���[�o���ϐ��̑���ӏ������������̂ŁA�O���[�o���ϐ����̂̃A�h���X�����߂�Bmov���߂̃I�y�����h���狁�߂Ă���B
				return *static_cast<const DWORD_PTR *>(static_cast<LPCVOID>(movToGlobalVarHint + 2)) - img.FileHeader->OptionalHeader.ImageBase;
				return 0;
			}
		}
	}
}
