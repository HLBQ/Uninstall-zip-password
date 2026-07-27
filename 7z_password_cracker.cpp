/** 7z Password Cracker v4 — 多线程批量处理 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <io.h>
#include <fcntl.h>
#include <Windows.h>
#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>

#include "bit7z.hpp"
#include "bitmemextractor.hpp"

#pragma pack(push, 1)
#define ERAR_BAD_PASSWORD       24
#define RAR_OM_EXTRACT          1
#define RAR_TEST                1
#define RAR_EXTRACT             2
#define RAR_OM_LIST_INCSPLIT    2

struct RARHeaderDataEx {
    char ArcName[1024]; wchar_t ArcNameW[1024]; char FileName[1024]; wchar_t FileNameW[1024];
    unsigned int Flags, PackSize, PackSizeHigh, UnpSize, UnpSizeHigh, HostOS;
    unsigned int FileCRC, FileTime, UnpVer, Method, FileAttr;
    char *CmtBuf; unsigned int CmtBufSize, CmtSize, CmtState;
    unsigned int DictSize, HashType; char Hash[32];
    unsigned int RedirType; wchar_t *RedirName; unsigned int RedirNameSize;
    unsigned int DirTarget; unsigned int MtimeLow, MtimeHigh, CtimeLow, CtimeHigh, AtimeLow, AtimeHigh;
    wchar_t *ArcNameEx; unsigned int ArcNameExSize;
    wchar_t *FileNameEx; unsigned int FileNameExSize; unsigned int Reserved[982];
};
struct RAROpenArchiveDataEx {
    char *ArcName; wchar_t *ArcNameW; unsigned int OpenMode, OpenResult;
    char *CmtBuf; unsigned int CmtBufSize, CmtSize, CmtState; unsigned int Flags;
    void* Callback; long UserData; unsigned int OpFlags;
    wchar_t *CmtBufW; wchar_t *MarkOfTheWeb; unsigned int Reserved2[23];
};
#pragma pack(pop)

namespace fs = std::filesystem;
using byte_t = unsigned char;
using namespace std;

// ===================== UTF-8 =====================
static string u8(const wstring& ws) {
    if (ws.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {}; string r(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &r[0], n, nullptr, nullptr); return r;
}
static string u8(uint64_t v) { return to_string(v); }
template<typename T, typename = enable_if_t<is_integral_v<T>>> static string u8(T v) { return to_string(v); }
static wstring w8(const string& s) {
    if (s.empty()) return {}; int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return {}; wstring r(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &r[0], n); return r;
}
template<typename... Args> static void msg(const wchar_t* fmt, Args&&... args) {
    string line = u8(fmt); (void)initializer_list<int>{((line += u8(args)), 0)...};
    line += '\n'; fwrite(line.data(), 1, line.size(), stdout); fflush(stdout);
}

// ===================== Format =====================
static const bit7z::BitInFormat& detectFmt(const wstring& p) {
    wstring e; size_t d = p.find_last_of(L'.');
    if (d != wstring::npos && d + 1 < p.length()) { e = p.substr(d+1); for (auto& c : e) c = towlower(c); }
    auto bi = [&](const wstring& i) -> const bit7z::BitInFormat* {
        if (i==L"7z"||i==L"gsp"||i==L"gspp") return &bit7z::BitFormat::SevenZip;
        if (i==L"zip") return &bit7z::BitFormat::Zip; if (i==L"rar") return &bit7z::BitFormat::Rar5;
        if (i==L"bz2") return &bit7z::BitFormat::BZip2; if (i==L"xz") return &bit7z::BitFormat::Xz;
        if (i==L"wim") return &bit7z::BitFormat::Wim; if (i==L"tar") return &bit7z::BitFormat::Tar;
        if (i==L"gz") return &bit7z::BitFormat::GZip; return nullptr;
    };
    if (e==L"001"||e==L"r00"||e==L"part1"||e==L"part01") {
        size_t s = p.find_last_of(L'.', d-1);
        if (s != wstring::npos && s+1 < d) { wstring in = p.substr(s+1,d-s-1); for (auto& c : in) c = towlower(c); auto* r = bi(in); if (r) return *r; }
    } auto* r = bi(e); if (r) return *r; return bit7z::BitFormat::SevenZip;
}
static const bit7z::BitInFormat& parseType(const string& s) {
    string l = s; for (auto& c : l) c = (char)tolower((unsigned char)c);
    if (l=="7z"||l=="gsp"||l=="gspp") return bit7z::BitFormat::SevenZip;
    if (l=="zip") return bit7z::BitFormat::Zip; if (l=="rar"||l=="rar5") return bit7z::BitFormat::Rar5;
    if (l=="bz2"||l=="bzip2") return bit7z::BitFormat::BZip2; if (l=="xz") return bit7z::BitFormat::Xz;
    if (l=="wim") return bit7z::BitFormat::Wim; if (l=="tar") return bit7z::BitFormat::Tar;
    if (l=="gz") return bit7z::BitFormat::GZip; return bit7z::BitFormat::SevenZip;
}
static const bit7z::BitInOutFormat& parseCompressType(const string& s) {
    string l = s; for (auto& c : l) c = (char)tolower((unsigned char)c);
    if (l=="7z"||l=="gsp"||l=="gspp") return bit7z::BitFormat::SevenZip;
    if (l=="zip") return bit7z::BitFormat::Zip;
    if (l=="bz2"||l=="bzip2") return bit7z::BitFormat::BZip2; if (l=="xz") return bit7z::BitFormat::Xz;
    if (l=="wim") return bit7z::BitFormat::Wim; if (l=="tar") return bit7z::BitFormat::Tar;
    if (l=="gz") return bit7z::BitFormat::GZip;
    return bit7z::BitFormat::Zip; // 默认
}

// ===================== Config =====================
enum class CacheMode { Auto, Force, Disable };
struct CmdConfig {
    wstring archivePath, outDir, extractPwd, dictPath, pbPath;
    wstring compressSrc, compressName; // -z 打包源, -n 压缩包名称
    int bruteMinLen = 0, bruteMaxLen = 0;
    int compressK = 5; // -k 压缩质量, 默认5
    string compressType = "zip"; // -i 压缩类型, 默认zip
    uint64_t startN = 1, endN = 0, printStep = 1;
    string fileType;
    CacheMode cache = CacheMode::Auto;
    bool isRar = false, isExtract = false, isCompress = false, hasDict = false, hasPb = false;
    bool compressDelete = false; // -d 压缩后删除原文件
    int threads = 1;     // -tr, 1=默认单线程
    int batchSize = 2048; // -bt, 多线程下每批任务数
};

// ===================== Parse =====================
static CmdConfig parseArgs(int argc, wchar_t* argv[]) {
    CmdConfig cfg; if (argc < 3) return cfg;
    wstring first = argv[1];
    cfg.isExtract = (first == L"-e");
    cfg.isCompress = (first == L"-z");
    if (cfg.isExtract) cfg.archivePath = (argc >= 3) ? argv[2] : L"";
    else if (cfg.isCompress) cfg.compressSrc = (argc >= 3) ? argv[2] : L"";
    else cfg.archivePath = first;
    int ns = (cfg.isExtract || cfg.isCompress) ? 3 : 2;
    for (int i = ns; i < argc; ++i) {
        wstring a = argv[i];
        if (a == L"-o"&&i+1<argc) { cfg.outDir=argv[++i]; continue; }
        if (a == L"-n"&&i+1<argc) { cfg.compressName=argv[++i]; continue; }
        if (a == L"-i"&&i+1<argc) { cfg.compressType=u8(wstring(argv[++i])); continue; }
        if (a == L"-k"&&i+1<argc) {
            if (cfg.isCompress) { cfg.compressK=(int)wcstoul(argv[++i],0,10); if (cfg.compressK<0) cfg.compressK=0; if (cfg.compressK>9) cfg.compressK=9; }
            else { cfg.fileType=u8(wstring(argv[++i])); }
            continue;
        }
        if (a == L"-c"&&i+1<argc) { cfg.dictPath=argv[++i]; cfg.hasDict=true; continue; }
        if (a == L"-p"&&i+1<argc) { cfg.pbPath=argv[++i]; cfg.hasPb=true; continue; }
        if (a == L"-ts"&&i+1<argc) { cfg.bruteMinLen=(int)wcstoul(argv[++i],0,10); continue; }
        if (a == L"-te"&&i+1<argc) { cfg.bruteMaxLen=(int)wcstoul(argv[++i],0,10); continue; }
        if (a == L"-s"&&i+1<argc) { cfg.startN=wcstoull(argv[++i],0,10); continue; }
        if (a == L"-e"&&i+1<argc) { cfg.endN=wcstoull(argv[++i],0,10); continue; }
        if (a == L"-ps"&&i+1<argc) { cfg.extractPwd=argv[++i]; continue; }
        if (a == L"-tr"&&i+1<argc) { cfg.threads=(int)wcstoul(argv[++i],0,10); continue; }
        if (a == L"-bt"&&i+1<argc) { cfg.batchSize=(int)wcstoul(argv[++i],0,10); if (cfg.batchSize<1) cfg.batchSize=1; continue; }
        if (a == L"-pt"&&i+1<argc) { cfg.printStep=wcstoull(argv[++i],0,10); continue; }
        if (a == L"-d") { cfg.compressDelete=true; continue; }
        if (a == L"-b") { cfg.cache=CacheMode::Force; continue; }
        if (a == L"-nb") { cfg.cache=CacheMode::Disable; continue; }
    }
    if (!cfg.archivePath.empty()) {
        size_t dp = cfg.archivePath.find_last_of(L'.');
        if (dp != wstring::npos) {
            wstring e = cfg.archivePath.substr(dp); for (auto& c : e) c = towlower(c);
            cfg.isRar = (e==L".rar"||e.find(L".part")!=wstring::npos||e==L".r00"||e==L".part1"||e==L".part01");
        }
    }
    return cfg;
}

// ===================== Brute-force =====================
static uint64_t powSat(int b, int e) {
    uint64_t r=1; for (int i=0;i<e;++i) { uint64_t p=r; r*=b; if (r/b!=p) return UINT64_MAX; } return r;
}
static uint64_t totalRange(int c, int ts, int te) {
    uint64_t s=0; for (int i=ts;i<=te;++i) { uint64_t p=powSat(c,i); if (p==UINT64_MAX) return UINT64_MAX; uint64_t pr=s; s+=p; if (s<pr) return UINT64_MAX; } return s;
}
static wstring idxPwd(uint64_t idx, const wstring& cs, int ts, int te) {
    int n=(int)cs.size(); uint64_t off=idx; int len=ts;
    for (int L=ts;L<=te;++L) { uint64_t cnt=powSat(n,L); if (off<cnt) { len=L; break; } off-=cnt; }
    wstring r; r.reserve(len); uint64_t rem=off;
    for (int i=0;i<len;++i) { r.push_back(cs[rem%n]); rem/=n; }
    reverse(r.begin(),r.end()); return r;
}

// ===================== File =====================
static vector<wstring> loadLines(const wstring& p) {
    vector<wstring> l; FILE* f=_wfopen(p.c_str(),L"rb"); if (!f) return l;
    char buf[4096]; string left;
    while (fgets(buf,sizeof(buf),f)) { left+=buf; size_t pos;
        while ((pos=left.find('\n'))!=string::npos) {
            string line=left.substr(0,pos); left.erase(0,pos+1);
            if (!line.empty()&&line.back()=='\r') line.pop_back();
            if (!line.empty()) l.push_back(w8(line));
        }
    }
    if (!left.empty()) { if (left.back()=='\r') left.pop_back(); if (!left.empty()) l.push_back(w8(left)); }
    fclose(f); return l;
}

// ===================== Generator =====================
struct PwdBook {
    vector<wstring> lines; wstring charset; int ts=0, te=0; uint64_t bc=0;
    uint64_t total() const {
        uint64_t c=(ts>0&&te>0)?totalRange((int)charset.size(),ts,te):0;
        if (c==UINT64_MAX) return UINT64_MAX; uint64_t t=bc+c; if (t<bc) return UINT64_MAX; return t;
    }
    wstring get(uint64_t i) const { if (i<bc) return lines[(size_t)i]; return idxPwd(i-bc,charset,ts,te); }
};

// ===================== Verify =====================
enum class TestResult { Success, WrongPassword, Error };
static auto isPwdErr = [](const wstring& m) -> bool {
    wstring l=m; for (auto& c:l) c=towlower(c);
    return l.find(L"wrong password")!=wstring::npos||l.find(L"unknown error")!=wstring::npos||
           l.find(L"data error")!=wstring::npos||l.find(L"crc")!=wstring::npos||
           l.find(L"incorrect")!=wstring::npos||l.find(L"password")!=wstring::npos;
};

struct ExtractorCtx {
    unique_ptr<bit7z::BitExtractor> fileEx;
    unique_ptr<bit7z::BitMemExtractor> memEx;
    void init(const bit7z::Bit7zLibrary& l, const bit7z::BitInFormat& f, bool useMem) {
        if (useMem) memEx.reset(new bit7z::BitMemExtractor(l,f)); else fileEx.reset(new bit7z::BitExtractor(l,f));
    }
    TestResult test(const wstring& path, const vector<byte_t>* data, const wstring& pwd, wstring& err) {
        try {
            if (memEx) { memEx->setPassword(pwd); memEx->test(*data); }
            else { fileEx->setPassword(pwd); fileEx->test(path); }
            return TestResult::Success;
        } catch (const bit7z::BitException& e) { wstring m=w8(e.what()); if (isPwdErr(m)) return TestResult::WrongPassword; err=m; return TestResult::Error; }
    }
};

// 单次测试封装 (密码本阶段用)
static TestResult tryPwd7z(ExtractorCtx& ctx, const wstring& path, const vector<byte_t>* data, const wstring& pwd, wstring& err) {
    return ctx.test(path, data, pwd, err);
}

// ===================== RAR fast-try (unrar.dll) =====================
static TestResult tryPwdRarFast(const wstring& path, const wstring& pwd, const wstring& dllPath) {
    HMODULE hU=LoadLibraryW(dllPath.c_str()); if (!hU) return TestResult::Error;
    auto pO=(HANDLE(PASCAL*)(RAROpenArchiveDataEx*))GetProcAddress(hU,"RAROpenArchiveEx");
    auto pC=(int(PASCAL*)(HANDLE))GetProcAddress(hU,"RARCloseArchive");
    auto pR=(int(PASCAL*)(HANDLE,RARHeaderDataEx*))GetProcAddress(hU,"RARReadHeaderEx");
    auto pS=(void(PASCAL*)(HANDLE,char*))GetProcAddress(hU,"RARSetPassword");
    if (!pO||!pC||!pR||!pS) { FreeLibrary(hU); return TestResult::Error; }
    char aA[1024],aP[1024]; WideCharToMultiByte(CP_ACP,0,path.c_str(),-1,aA,1024,nullptr,nullptr); WideCharToMultiByte(CP_ACP,0,pwd.c_str(),-1,aP,1024,nullptr,nullptr);
    RAROpenArchiveDataEx od={}; od.ArcName=aA; od.ArcNameW=(wchar_t*)path.c_str(); od.OpenMode=RAR_OM_LIST_INCSPLIT; od.Callback=nullptr; od.UserData=0; od.OpFlags=0;
    HANDLE hA=pO(&od); if (!hA||od.OpenResult!=0) { if (hA) pC(hA); FreeLibrary(hU); return TestResult::Error; }
    pS(hA,aP); RARHeaderDataEx hd={}; int rc=pR(hA,&hd); pC(hA); FreeLibrary(hU);
    if (rc==ERAR_BAD_PASSWORD) return TestResult::WrongPassword;
    if (rc!=0) return TestResult::Error;
    return TestResult::Success;
}

// ===================== Volume merge =====================
static wstring mergeVols(const wstring& src, wstring& outPath) {
    size_t dp=src.find_last_of(L'.'); if (dp==wstring::npos) return src;
    wstring ext=src.substr(dp+1); for (auto& c:ext) c=towlower(c);
    int d=0,s=0; if (ext==L"001"){d=3;s=1;} else if (ext==L"r00"){d=0;s=0;} else if (ext==L"part1"){d=1;s=1;} else if (ext==L"part01"){d=2;s=1;} else return src;
    wstring base=src.substr(0,dp+1); wchar_t td[MAX_PATH]; GetTempPathW(MAX_PATH,td); wchar_t tf[MAX_PATH]; GetTempFileNameW(td,L"7zv",0,tf); DeleteFileW(tf); outPath=tf;
    HANDLE hO=CreateFileW(outPath.c_str(),GENERIC_WRITE,0,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
    if (hO==INVALID_HANDLE_VALUE) { msg(L"[ERROR]|无法创建临时文件"); return src; }
    char buf[65536]; int vn=s; uint64_t tot=0;
    while (true) {
        wstring vp; if (d>0) { wchar_t nb[16]; swprintf_s(nb,L"%0*d",d,vn); vp=base+nb; }
        else { wstring ns=to_wstring(vn); if (ns.size()<2) ns=L"0"+ns; vp=base+L"r"+ns; }
        HANDLE hI=CreateFileW(vp.c_str(),GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
        if (hI==INVALID_HANDLE_VALUE) break; DWORD br,bw; while (ReadFile(hI,buf,sizeof(buf),&br,0)&&br>0) { WriteFile(hO,buf,br,&bw,0); tot+=bw; } CloseHandle(hI); vn++;
    } CloseHandle(hO); msg(L"[INFO]|分卷合并完成, 共",(size_t)(tot/1024/1024),L"MB"); return outPath;
}

// ===================== Memory cache =====================
struct MemArchive { vector<byte_t> data; bool valid=false;
    void load(const wstring& path, bool force) {
        HANDLE hF=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
        if (hF==INVALID_HANDLE_VALUE) return; LARGE_INTEGER fs; GetFileSizeEx(hF,&fs); uint64_t sz=(uint64_t)fs.QuadPart; CloseHandle(hF);
        if (!force&&sz>1024ULL*1024*1024) { msg(L"[INFO]|压缩包超过1GB, 跳过缓存"); return; }
        if (!force) { MEMORYSTATUSEX mem={sizeof(mem)}; GlobalMemoryStatusEx(&mem); if (sz>mem.ullAvailPhys/2) { msg(L"[INFO]|内存不足, 跳过缓存"); return; } }
        try { data.resize((size_t)sz); FILE* f=_wfopen(path.c_str(),L"rb"); if (!f) return; size_t rd=fread(data.data(),1,(size_t)sz,f); fclose(f);
            if (rd==(size_t)sz) { if (sz>=1024*1024) msg(L"[INFO]|缓存: ",(size_t)(sz/1024/1024),L"MB"); else if (sz>=1024) msg(L"[INFO]|缓存: ",(size_t)(sz/1024),L"KB"); else msg(L"[INFO]|缓存: ",(size_t)sz,L"B"); valid=true; } }
        catch (bad_alloc&) { msg(L"[WARN]|内存不足"); data.clear(); }
    }
};

// ===================== Main =====================
int wmain(int argc, wchar_t* argv[]) {
    SetConsoleOutputCP(CP_UTF8); (void)_setmode(_fileno(stdout), _O_BINARY);
    CmdConfig cfg = parseArgs(argc, argv);
    if (argc < 3 || (!cfg.isCompress && cfg.archivePath.empty())) {
        msg(L"[ERROR]|用法:"); 
        msg(L"  打包: 7z_to_dll.exe -z <目录/文件> -o <生成位置> [-n <名称>] [-k <质量>] [-i <类型>] [-d]");
        msg(L"  解压: 7z_to_dll.exe -e <压缩包> [-o <目录>] [-ps <密码>]");
        msg(L"  破解: 7z_to_dll.exe <压缩包> -c <字符集> -ts N -te N [-p <密码本>] [-s N] [-e N] [-b|-nb] [-tr N] [-bt N]"); return 1;
    }

    // ===== COMPRESS =====
    if (cfg.isCompress) {
        if (cfg.compressSrc.empty()) { msg(L"[ERROR]|请指定打包源"); return 1; }
        if (cfg.outDir.empty()) { msg(L"[ERROR]|-o 生成位置必填"); return 1; }
        DWORD srcAttr = GetFileAttributesW(cfg.compressSrc.c_str());
        if (srcAttr == INVALID_FILE_ATTRIBUTES) { msg(L"[ERROR]|打包源不存在"); return 3; }
        wchar_t ed[1024] = {}; GetModuleFileNameW(0, ed, 1024); wstring ddd(ed); size_t ls = ddd.find_last_of(L"\\/"); wstring es = (ls != wstring::npos) ? ddd.substr(0, ls + 1) : L".";
        const wchar_t* dl[] = { L"7z_26.dll",L"7z_22.dll",L"7z_19.dll" }; bit7z::Bit7zLibrary* pL = 0;
        for (auto d : dl) { wstring dp = es + d; if (GetFileAttributesW(dp.c_str()) != INVALID_FILE_ATTRIBUTES && LoadLibraryW(dp.c_str())) { FreeLibrary(GetModuleHandleW(dp.c_str())); pL = new bit7z::Bit7zLibrary(dp); break; } }
        if (!pL) { msg(L"[ERROR]|无法加载7z DLL"); return 11; }
        // 确定压缩格式和扩展名
        const bit7z::BitInOutFormat& cmpFmt = parseCompressType(cfg.compressType);
        wstring defExt = w8(cfg.compressType);
        if (defExt.empty() || defExt == L"7z" || defExt == L"gsp" || defExt == L"gspp") defExt = L"7z";
        // 生成输出路径: outDir\name.ext
        wstring outName = cfg.compressName;
        if (outName.empty()) {
            size_t sp = cfg.compressSrc.find_last_of(L"\\/"); wstring baseName = (sp != wstring::npos) ? cfg.compressSrc.substr(sp + 1) : cfg.compressSrc;
            outName = baseName + L"." + defExt;
        } else {
            if (outName.find(L'.') == wstring::npos) outName += L"." + defExt;
        }
        wstring outPath = cfg.outDir;
        if (!outPath.empty() && outPath.back() != L'\\' && outPath.back() != L'/') outPath += L'\\';
        outPath += outName;
        (void)CreateDirectoryW(cfg.outDir.c_str(), 0);
        // 压缩级别映射: BitCompressionLevel: NONE=0 FASTEST=1 FAST=3 NORMAL=5 MAX=7 ULTRA=9
        bit7z::BitCompressionLevel lvl;
        switch (cfg.compressK) {
            case 0: lvl = bit7z::BitCompressionLevel::NONE; break;
            case 1: case 2: lvl = bit7z::BitCompressionLevel::FASTEST; break;
            case 3: case 4: lvl = bit7z::BitCompressionLevel::FAST; break;
            case 5: case 6: lvl = bit7z::BitCompressionLevel::NORMAL; break;
            case 7: case 8: lvl = bit7z::BitCompressionLevel::MAX; break;
            case 9: lvl = bit7z::BitCompressionLevel::ULTRA; break;
            default: lvl = bit7z::BitCompressionLevel::NORMAL; break;
        }
        try {
            bit7z::BitCompressor cmp(*pL, cmpFmt);
            cmp.setCompressionLevel(lvl);
            uint64_t totalSize = 0;
            cmp.setTotalCallback([&totalSize](uint64_t ts) { totalSize = ts; });
            cmp.setProgressCallback([&totalSize](uint64_t p) { if (totalSize > 0) msg(L"[COMPRESS]|", (size_t)(p * 100 / totalSize)); });
            bool isDir = (srcAttr & FILE_ATTRIBUTE_DIRECTORY) != 0;
            if (isDir) {
                msg(L"[INFO]|压缩目录: ", cfg.compressSrc, L" → ", outPath, L" 等级=", (int)lvl);
                cmp.compressDirectory(cfg.compressSrc, outPath);
            } else {
                msg(L"[INFO]|压缩文件: ", cfg.compressSrc, L" → ", outPath, L" 等级=", (int)lvl);
                cmp.compressFile(cfg.compressSrc, outPath);
            }
            if (cfg.compressDelete) {
                msg(L"[INFO]|删除原文件: ", cfg.compressSrc);
                error_code ec;
                fs::remove_all(cfg.compressSrc, ec);
            }
            msg(L"[DONE]|打包完成 → ", outPath);
            delete pL; return 0;
        } catch (const bit7z::BitException& e) { msg(L"[ERROR]|打包失败: ", w8(e.what())); delete pL; return 7; }
    }

    if (GetFileAttributesW(cfg.archivePath.c_str())==INVALID_FILE_ATTRIBUTES) { msg(L"[ERROR]|压缩包不存在"); return 3; }

    if (cfg.isExtract) {
        if (cfg.outDir.empty()) { size_t dp=cfg.archivePath.find_last_of(L'.'); cfg.outDir=cfg.archivePath.substr(0,dp); size_t sp=cfg.outDir.find_last_of(L"\\/"); if (sp!=wstring::npos) cfg.outDir=cfg.outDir.substr(sp+1); }
        wchar_t ed[1024]={}; GetModuleFileNameW(0,ed,1024); wstring ddd(ed); size_t ls=ddd.find_last_of(L"\\/"); wstring es=(ls!=wstring::npos)?ddd.substr(0,ls+1):L".";
        const wchar_t* dl[]={L"7z.dll"}; bit7z::Bit7zLibrary* pL=0;
        for (auto d:dl) { wstring dp=es+d; if (GetFileAttributesW(dp.c_str())!=INVALID_FILE_ATTRIBUTES&&LoadLibraryW(dp.c_str())) { FreeLibrary(GetModuleHandleW(dp.c_str())); pL=new bit7z::Bit7zLibrary(dp); break; } }
        if (!pL) { msg(L"[ERROR]|无法加载7z DLL"); return 11; }
        const auto& fmt=cfg.fileType.empty()?detectFmt(cfg.archivePath):parseType(cfg.fileType);
        wstring mf,ep=mergeVols(cfg.archivePath,mf); bool mg=(ep!=cfg.archivePath); if (mg) msg(L"[INFO]|分卷已合并");
        (void)CreateDirectoryW(cfg.outDir.c_str(),0);
        try { bit7z::BitExtractor ex(*pL,fmt); ex.setPassword(cfg.extractPwd); uint64_t ts=0; ex.setTotalCallback([&ts](uint64_t s){ts=s;}); ex.setProgressCallback([&ts](uint64_t p){if(ts>0)msg(L"[EXTRACT]|",(size_t)(p*100/ts));});
            msg(L"[INFO]|开始解压 → ",cfg.outDir); ex.extract(ep,cfg.outDir);
            if (cfg.compressDelete) {
                msg(L"[INFO]|删除压缩包: ", cfg.archivePath);
                error_code ec;
                fs::remove(cfg.archivePath, ec);
            }
            msg(L"[DONE]|解压完成");
            if (mg) DeleteFileW(mf.c_str()); delete pL; return 0; }
        catch (const bit7z::BitException& e) { msg(L"[ERROR]|解压失败: ",w8(e.what())); if (mg) DeleteFileW(mf.c_str()); delete pL; return 7; }
    }

    // ===== CRACK =====
    if (!cfg.hasDict&&!cfg.hasPb) { msg(L"[ERROR]|请指定字典(-c)或密码本(-p)"); return 1; }
    if (cfg.hasDict&&(cfg.bruteMinLen<=0||cfg.bruteMaxLen<=0)) { msg(L"[ERROR]|-c 必须配合 -ts 和 -te"); return 1; }

    vector<wstring> pbLines;
    if (cfg.hasPb) {
        if (GetFileAttributesW(cfg.pbPath.c_str())==INVALID_FILE_ATTRIBUTES) { msg(L"[ERROR]|密码本不存在"); return 2; }
        pbLines=loadLines(cfg.pbPath); if (pbLines.empty()) { msg(L"[ERROR]|密码本为空"); return 4; }
        msg(L"[INFO]|密码本加载完成, 共",pbLines.size(),L"行");
    }

    wstring charset;
    if (cfg.hasDict) {
        if (GetFileAttributesW(cfg.dictPath.c_str())==INVALID_FILE_ATTRIBUTES) { msg(L"[ERROR]|字典文件不存在"); return 2; }
        auto lines=loadLines(cfg.dictPath); if (lines.empty()) { msg(L"[ERROR]|字典为空"); return 4; }
        charset=lines[0]; if (charset.empty()) { msg(L"[ERROR]|字符集为空"); return 4; }
        if (cfg.bruteMinLen<1) cfg.bruteMinLen=1; if (cfg.bruteMaxLen<cfg.bruteMinLen) cfg.bruteMaxLen=cfg.bruteMinLen;
        msg(L"[INFO]|暴力: 字符集=",charset,L" 长度",cfg.bruteMinLen,L"-",cfg.bruteMaxLen);
    }

    PwdBook book; if (cfg.hasPb) { book.lines=pbLines; book.bc=pbLines.size(); }
    if (cfg.hasDict) { book.charset=charset; book.ts=cfg.bruteMinLen; book.te=cfg.bruteMaxLen; }

    uint64_t totalPwds=book.total(); if (totalPwds==0) { msg(L"[ERROR]|无有效密码"); return 4; }
    uint64_t startIdx=(cfg.startN<1)?0:cfg.startN-1;
    uint64_t endIdx=(cfg.endN==0)?UINT64_MAX:cfg.endN-1;
    if (startIdx>=totalPwds) { msg(L"[ERROR]|断点超出总数"); return 5; }

    wchar_t ed[1024]={}; GetModuleFileNameW(0,ed,1024); wstring ddd(ed); size_t ls=ddd.find_last_of(L"\\/"); wstring es=(ls!=wstring::npos)?ddd.substr(0,ls+1):L".";
    const wchar_t* dl[]={L"7z_26.dll",L"7z_22.dll",L"7z_19.dll"}; bit7z::Bit7zLibrary* pL=0;
    for (auto d:dl) { wstring dp=es+d; if (GetFileAttributesW(dp.c_str())!=INVALID_FILE_ATTRIBUTES&&LoadLibraryW(dp.c_str())) { FreeLibrary(GetModuleHandleW(dp.c_str())); pL=new bit7z::Bit7zLibrary(dp); break; } }
    if (!pL&&!cfg.isRar) { msg(L"[ERROR]|无法加载7z DLL"); return 11; }
    wstring urDll=es+L"unrar.dll"; const auto& fmt=cfg.fileType.empty()?detectFmt(cfg.archivePath):parseType(cfg.fileType);
    msg(L"[DBG]|exe目录: ",es);

    wstring mf, testPath=cfg.archivePath; bool isMerged=false;
    if (!cfg.isRar) { testPath=mergeVols(cfg.archivePath,mf); isMerged=(testPath!=cfg.archivePath); if (isMerged) msg(L"[INFO]|使用合并后文件"); }
    else msg(L"[INFO]|RAR: 直接使用原始分卷");

    bool useCache=false;
    if (cfg.isRar) useCache=false; else if (cfg.cache==CacheMode::Force) useCache=true; else if (cfg.cache==CacheMode::Disable) useCache=false;
    else { HANDLE hT=CreateFileW(testPath.c_str(),GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
        if (hT!=INVALID_HANDLE_VALUE) { LARGE_INTEGER fsz; GetFileSizeEx(hT,&fsz); CloseHandle(hT); useCache=((uint64_t)fsz.QuadPart<=1024ULL*1024*1024); } }
    MemArchive mA; if (useCache) { mA.load(testPath,cfg.cache==CacheMode::Force); if (!mA.valid) { msg(L"[INFO]|回退磁盘"); useCache=false; } }

    int nThreads=cfg.threads; if (nThreads<=0) nThreads=(int)thread::hardware_concurrency(); if (nThreads<1) nThreads=1;
    int bsz=cfg.batchSize; if (bsz<1) bsz=2048;

    msg(L"[START]|总数=",totalPwds,L"|起始=",startIdx+1,L"|结束=",(endIdx==UINT64_MAX?L"末尾":to_wstring(endIdx+1)),
        L"|线程=",nThreads,L"|批次=",bsz);
    msg(L"[INFO]|密码本=",book.bc,L"条|组合=",(totalPwds-book.bc),L"条");

    bool found=false;
    mutex outMtx; atomic<bool> stopFlag{false}; uint64_t lastReported=startIdx;

    // === 阶段1: 密码本 (单线程, 逐条) ===
    uint64_t pbEnd=min(book.bc,(endIdx==UINT64_MAX?book.bc:endIdx+1));
    for (uint64_t i=startIdx; i<pbEnd&&!stopFlag.load(); ++i) {
        wstring pwd=book.get(i); msg(L"[STATUS]|",i+1,L"|",totalPwds,L"|",pwd);
        wstring err; TestResult r; ExtractorCtx ctx; ctx.init(*pL,fmt,useCache);
        if (cfg.isRar) { r=tryPwdRarFast(testPath,pwd,urDll);
            if (r==TestResult::Success) { /* verify later */ r=tryPwd7z(ctx,testPath,useCache?&mA.data:nullptr,pwd,err); } }
        else r=tryPwd7z(ctx,testPath,useCache?&mA.data:nullptr,pwd,err);
        if (r==TestResult::Success) { msg(L"[FOUND]|",pwd); found=true; stopFlag.store(true); break; }
        if (r==TestResult::Error) { msg(L"[ERROR]|",err); if (isMerged) DeleteFileW(mf.c_str()); delete pL; return 7; }
    }

    // === 阶段2: 暴力组合 ===
    if (!stopFlag.load()&&totalPwds>book.bc) {
        uint64_t brStart=max(startIdx,book.bc);
        uint64_t brEnd=min((endIdx==UINT64_MAX?totalPwds-1:endIdx),totalPwds-1);
        uint64_t brCount=(brEnd>=brStart)?(brEnd-brStart+1):0;
        uint64_t lastPreserved=brStart;

        // RAR 可靠性检测 (一次性)
        bool rarUse7z=false;
        if (cfg.isRar) {
            TestResult t1=tryPwdRarFast(testPath,L"__CHK_A__",urDll);
            TestResult t2=tryPwdRarFast(testPath,L"__CHK_B__",urDll);
            rarUse7z=(t1==TestResult::Success&&t2==TestResult::Success);
            if (rarUse7z) msg(L"[INFO]|RAR加密文件名, 使用7z解密");
            else msg(L"[INFO]|RAR普通, 使用unrar解密");
        }

        // 是否启用多线程: 任务数>线程数 且 线程数>1
        bool useMt=(brCount>(uint64_t)nThreads)&&(nThreads>1);
        if (useMt) msg(L"[INFO]|多线程暴力: ",nThreads,L"线程, 批次",bsz);
        else msg(L"[INFO]|单线程暴力, 任务数=",brCount);

        // === 多线程 (+ 批量报告) ===
        if (useMt) {
            atomic<uint64_t> nextAtom{brStart};
            atomic<uint64_t> doneCnt{0};

            // Worker 统一入口
            auto worker = [&](int tid) {
                // 每个 worker 独立的验证上下文 (始终初始化, 用于 rar uncrypt 阶段的 fallback)
                ExtractorCtx ctx;
                ctx.init(*pL, fmt, useCache);

                while (!stopFlag.load()) {
                    uint64_t base = nextAtom.fetch_add((uint64_t)bsz);
                    if (base > brEnd) break;
                    uint64_t lim = min(base + bsz - 1, brEnd);
                    for (uint64_t i = base; i <= lim && !stopFlag.load(); ++i) {
                        wstring pwd = book.get(i);
                        wstring err; TestResult r;
                        if (cfg.isRar && !rarUse7z) {
                            r = tryPwdRarFast(testPath, pwd, urDll);
                            if (r == TestResult::Success) { /* verify */ r = useCache ? ctx.test(L"", &mA.data, pwd, err) : ctx.test(testPath, nullptr, pwd, err); }
                        } else {
                            r = useCache ? ctx.test(L"", &mA.data, pwd, err) : ctx.test(testPath, nullptr, pwd, err);
                        }
                        if (r == TestResult::Success) {
                            lock_guard<mutex> lk(outMtx); msg(L"[FOUND]|",pwd); found = true; stopFlag.store(true); break;
                        }
                        if (r == TestResult::Error) {
                            lock_guard<mutex> lk(outMtx); msg(L"[ERROR]|",err); stopFlag.store(true); break;
                        }
                    }
                    if (!stopFlag.load()) {
                        uint64_t prev = doneCnt.fetch_add(bsz);
                        // 主线程每隔一个批次报告进度
                    }
                }
            };

            vector<thread> workers; workers.reserve(nThreads);
            for (int t=0; t<nThreads; ++t) workers.emplace_back(worker, t);

            // 主线程轮询进度 → 每完成 bsz 条报告一次
            while (!stopFlag.load()) {
                this_thread::sleep_for(chrono::milliseconds(100));
                uint64_t dc = doneCnt.load();
                uint64_t completed = dc;  // bsz * batch count
                uint64_t globalIdx = brStart + completed;
                if (globalIdx > brEnd) globalIdx = brEnd;
                if (completed > 0 && globalIdx != lastReported) {
                    wstring mpwd = book.get(globalIdx);
                    lock_guard<mutex> lk(outMtx);
                    msg(L"[STATUS]|", globalIdx+1, L"|", totalPwds, L"|", mpwd);
                    lastReported = globalIdx;
                }
            }
            for (auto& t : workers) if (t.joinable()) t.join();
        }

        // === 单线程暴力 ===
        else {
            ExtractorCtx ctx; if (!cfg.isRar||rarUse7z) ctx.init(*pL,fmt,useCache);
            for (uint64_t i=brStart; i<=brEnd&&!stopFlag.load(); ++i) {
                wstring pwd=book.get(i);
                bool brute=(i>=book.bc); bool sp=true;
                if (brute) { if (cfg.printStep==0) sp=false; else if (cfg.printStep>1) { uint64_t bi=i-book.bc; sp=(bi%cfg.printStep==0); } }
                if (sp) msg(L"[STATUS]|",i+1,L"|",totalPwds,L"|",pwd);
                wstring err; TestResult r;
                if (cfg.isRar&&!rarUse7z) {
                    r=tryPwdRarFast(testPath,pwd,urDll);
                    if (r==TestResult::Success) r=useCache?ctx.test(L"", &mA.data, pwd, err):ctx.test(testPath, nullptr, pwd, err);
                } else r=useCache?ctx.test(L"",&mA.data,pwd,err):ctx.test(testPath,nullptr,pwd,err);
                if (r==TestResult::Success) { msg(L"[FOUND]|",pwd); found=true; break; }
                if (r==TestResult::Error) { msg(L"[ERROR]|",err); if (isMerged) DeleteFileW(mf.c_str()); delete pL; return 7; }
            }
        }
    }

    if (isMerged) DeleteFileW(mf.c_str()); delete pL;
    if (found) return 0;
    msg(L"[DONE]|NOT_FOUND"); return 6;
}