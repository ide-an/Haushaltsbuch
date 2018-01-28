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
	やってることを大ざっぱに。
	1. SQVMのRTTI(TypeDescriptor)を見つける
	2. TypeDescriptor、RTTICompleteObjectLocatorと辿って、SQVMのvtableの先頭を見つける
	3. vtableのアドレスを代入するコードがSQVMのコンストラクタなはず、ということでSQVMのコンストラクタを見つける
	4. SQVMのコンストラクタ、sq_open、mysq_createと呼び出し元を辿る
	5. mysq_createの呼び出し元で、戻り値をグローバル変数に格納するコードを探し、そのグローバル変数のアドレスを特定する。
	*/
	LOADED_IMAGE img; // https://msdn.microsoft.com/ja-jp/library/windows/desktop/ms680349(v=vs.85).aspx
	if (!::pseudoMapAndLoad(&img)) {
		return 0;
	}
	// ここまででSectionsの先頭とSectionsの個数は分かっている。
	PIMAGE_SECTION_HEADER const text = GetSection(img, ".text");
	PIMAGE_SECTION_HEADER const rdata = GetSection(img, ".rdata");
	PIMAGE_SECTION_HEADER const data = GetSection(img, ".data");
	if (!text || !rdata || !data) {
		return 0;
	}
	PVOID const textBase = ImageRvaToVa(img.FileHeader, img.MappedAddress, text->VirtualAddress, nullptr); // https://msdn.microsoft.com/ja-jp/library/windows/desktop/ms680218(v=vs.85).aspx
	PVOID const dataBase = ImageRvaToVa(img.FileHeader, img.MappedAddress, data->VirtualAddress, nullptr); // data->VirtualAddressの値はImageBaseからの相対値ということで実際にはRVA。これをVAに変換する
	PVOID const rdataBase = ImageRvaToVa(img.FileHeader, img.MappedAddress, rdata->VirtualAddress, nullptr);
	// 単にVirutalSizeでも良さそうだが、SectionAlignmentを考慮して余計に追加している。
	DWORD const textSize = (text->Misc.VirtualSize + img.FileHeader->OptionalHeader.SectionAlignment - 1) & ~(img.FileHeader->OptionalHeader.SectionAlignment - 1);
	DWORD const dataSize = (data->Misc.VirtualSize + img.FileHeader->OptionalHeader.SectionAlignment - 1) & ~(img.FileHeader->OptionalHeader.SectionAlignment - 1);
	DWORD const rdataSize = (rdata->Misc.VirtualSize + img.FileHeader->OptionalHeader.SectionAlignment - 1) & ~(img.FileHeader->OptionalHeader.SectionAlignment - 1);

	// rdataじゃなくてdataなのか？
	LPCBYTE const sqvmRttiStr = static_cast<LPCBYTE>(memmem(dataBase, dataSize, ".?AUSQVM@@", 10)); // data領域からRTTIを探す
	// Reversing C++ pp.14 のTypeDescriptorを見つけている。
	// http://www.openrce.org/articles/full_view/21
	// 下記のnameが見つかる。
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
	// sqvmRttiStr - 8がTypeDescriptorの先頭。アドレス変換的なものだと思うが、この辺の詳しい計算がわからない。
	DWORD_PTR const sqvmRttiStrRef = sqvmRttiStr - 8 - static_cast<LPBYTE>(dataBase) + img.FileHeader->OptionalHeader.ImageBase + data->VirtualAddress;

	LPCBYTE const sqvmRtti = static_cast<LPCBYTE>(memmem(rdataBase, rdataSize, &sqvmRttiStrRef, sizeof DWORD_PTR));
	// rdataからTypeDescriptorを参照する部分を探す。ここで見つけたのはおそらくRTTICompleteObjectLocator.pTypeDescriptor
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
	// sqvmRtti - 12がRTTICompleteObjectLocatorの先頭。この辺の詳しい計算がわからない。
	DWORD_PTR const sqvmRttiRef = sqvmRtti - 12 - static_cast<LPBYTE>(rdataBase) + img.FileHeader->OptionalHeader.ImageBase + rdata->VirtualAddress;

	LPCBYTE const sqvmVtblRtti = static_cast<LPCBYTE>(memmem(rdataBase, rdataSize, &sqvmRttiRef, 4));
	// ここでvtableを見つける。vtableの「1個前」にRTTICompleteObjectLocatorへのポインタが入ってる。
	// http://www.openrce.org/articles/img/igor2_rtti1.gif および Reversing C++ pp.13
	if (!sqvmVtblRtti) {
		return 0;
	}
	// vtableの先頭アドレスを求める。
	DWORD_PTR const sqvmVtblRef = sqvmVtblRtti + 4 - static_cast<LPBYTE>(rdataBase) + img.FileHeader->OptionalHeader.ImageBase + rdata->VirtualAddress;

	LPCBYTE const sqvmCtorHint = static_cast<LPCBYTE>(memmem(textBase, textSize, &sqvmVtblRef, sizeof DWORD_PTR));
	// vtableを参照するコードを探す。コンストラクタのコード断片が見つかるはず。
	// 憑依華ver 1.03の場合、0x58c42a
	if (!sqvmCtorHint) {
		return 0;
	}

	// コンストラクタの先頭アドレスを求める。sqvmCtorHeadは関数のプロローグ。以下に対応する機械語。
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
		// SQVMのコンストラクタの呼び出し元を見つける。SquirrelのコードでSQVMのコンストラクタを呼ぶのはsq_open()とsq_newthread()。
		// 憑依華ではsq_open()を呼んでいると仮定。
		LPCBYTE const sq_openHint = static_cast<LPCBYTE>(findNearCall(sq_openHintBase, sq_openHintSize, sqvmCtor));
		if (!sq_openHint) {
			return 0;
		}
		sq_openHintSize -= sq_openHint - sq_openHintBase;
		sq_openHintBase = sq_openHint + 1;

		// sq_open()の先頭アドレスを求める。ここも関数のプロローグを使って検索する。
		BYTE const sq_openHead[] = { 0x55, 0x8B, 0xEC }; // push ebp; mov ebp, esp
		LPCBYTE const sq_open = static_cast<LPCBYTE>(memmem(sq_openHint - 0x48, 0x48, sq_openHead, sizeof sq_openHead));
		if (!sq_open) {
			continue;
		}

		LPCBYTE mysq_createHintbase = static_cast<LPCBYTE>(textBase);
		DWORD mysq_createHintSize = textSize;
		for (;;) {
			// sq_open()の呼び出し元を見つける。この辺はスクリプトエンジンの外、黄昏フロ独自コードと思われる。
			LPCBYTE const mysq_createHint = static_cast<LPCBYTE>(findNearCall(mysq_createHintbase, mysq_createHintSize, sq_open));
			if (!mysq_createHint) {
				break;
			}
			/*
				; 憑依華ver 1.03の場合
				.text:00424690 sub_424690      proc near               ; CODE XREF: sub_40D530+17Cp
				.text:00424690                                         ; sub_455E10+29p
				.text:00424690                 push    esi
				.text:00424691                 push    400h
				.text:00424696                 call    sub_5840B0      ;; ここがsq_open()の呼び出し
				.text:0042469B                 mov     esi, eax        ;; 戻り値でSQVMが返ってくる。
				; この関数はその後esiをいろいろな関数に渡した後、SQVMを戻り値として返す。
				; なのでこの関数の呼び出し元を探す。
				; sub_424690 == mysq_create
			*/
			mysq_createHintSize -= mysq_createHint - mysq_createHintbase;
			mysq_createHintbase = mysq_createHint + 1;

			// mysq_createの呼び出し元を探す。プロローグを探すのではなく、そのアドレスがNear Callで呼ばれているかでmysq_create()の先頭かどうか判定する。
			LPCBYTE mysq_initHint;
			int mysq_initHintFindOffset = 1;
			for (; mysq_initHintFindOffset <= 0x30; ++mysq_initHintFindOffset) {
				LPCBYTE const mysq_create = mysq_createHint - mysq_initHintFindOffset; // push reg32; push imm32(0x400)
				mysq_initHint = static_cast<LPCBYTE>(findNearCall(textBase, textSize, mysq_create));
				if (mysq_initHint) {
					// mysq_initHintがmysq_create()の呼び出し元
					break;
				}
			}
			// mysq_create()の戻り値は、esiを経由して、とあるグローバル変数に格納される。ということでmysq_create()の呼び出し以降でそういったコードを探す。
			// .text : 0040D6AC                 call    sub_424690 ; mysq_create()の呼び出し
			// .text : 0040D6B1                 mov     esi, eax ; 戻り値がesiへ
			// .text : 0040D6B3                 mov     dword_8DACC0, 0
			// .text : 0040D6BD                 lea     eax, [ebp + var_74]
			// .text : 0040D6C0                 mov     dword_XXXXXXXX, esi ; ここが代入の箇所。機械語だと「89 35 XX XX XX XX」。
			if (mysq_initHintFindOffset <= 0x20) {
				BYTE const movToGlobalVarHintOps[] = { 0x89, 0x35 }; // mov ds:[imm32], esi
				LPCBYTE const movToGlobalVarHint = static_cast<LPCBYTE>(memmem(mysq_initHint + 5, 0x20, movToGlobalVarHintOps, sizeof movToGlobalVarHintOps));
				if (!movToGlobalVarHint) {
					continue;
				}
				// グローバル変数の代入箇所が見つかったので、グローバル変数自体のアドレスを求める。mov命令のオペランドから求めている。
				return *static_cast<const DWORD_PTR *>(static_cast<LPCVOID>(movToGlobalVarHint + 2)) - img.FileHeader->OptionalHeader.ImageBase;
				return 0;
			}
		}
	}
}
