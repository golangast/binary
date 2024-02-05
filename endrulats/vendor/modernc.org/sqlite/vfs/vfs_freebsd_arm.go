// Code generated by 'ccgo -o vfs__.go c/vfs.c -I../testdata/sqlite-amalgamation-3390300 -lmodernc.org/sqlite/lib -pkgname vfs -nocapi -export-externs X -D SQLITE_OS_UNIX -hide=vfsFullPathname -hide=vfsOpen -hide=vfsRead -hide=vfsAccess -hide=vfsFileSize -hide=vfsClose', DO NOT EDIT.

package vfs

import (
	"math"
	"reflect"
	"sync/atomic"
	"unsafe"

	"modernc.org/libc"
	"modernc.org/libc/sys/types"
	"modernc.org/sqlite/lib"
)

var _ = math.Pi
var _ reflect.Kind
var _ atomic.Value
var _ unsafe.Pointer
var _ *libc.TLS
var _ types.Size_t

type ptrdiff_t = int32

type size_t = uint32

type wchar_t = uint32

type va_list = uintptr

type sqlite_int64 = int64
type sqlite_uint64 = uint64
type sqlite3_int64 = sqlite_int64
type sqlite3_uint64 = sqlite_uint64

type sqlite3_callback = uintptr

type sqlite3_file1 = struct{ pMethods uintptr }

type sqlite3_file = sqlite3_file1
type sqlite3_io_methods1 = struct {
	iVersion               int32
	xClose                 uintptr
	xRead                  uintptr
	xWrite                 uintptr
	xTruncate              uintptr
	xSync                  uintptr
	xFileSize              uintptr
	xLock                  uintptr
	xUnlock                uintptr
	xCheckReservedLock     uintptr
	xFileControl           uintptr
	xSectorSize            uintptr
	xDeviceCharacteristics uintptr
	xShmMap                uintptr
	xShmLock               uintptr
	xShmBarrier            uintptr
	xShmUnmap              uintptr
	xFetch                 uintptr
	xUnfetch               uintptr
}

type sqlite3_io_methods = sqlite3_io_methods1

type sqlite3_vfs1 = struct {
	iVersion          int32
	szOsFile          int32
	mxPathname        int32
	pNext             uintptr
	zName             uintptr
	pAppData          uintptr
	xOpen             uintptr
	xDelete           uintptr
	xAccess           uintptr
	xFullPathname     uintptr
	xDlOpen           uintptr
	xDlError          uintptr
	xDlSym            uintptr
	xDlClose          uintptr
	xRandomness       uintptr
	xSleep            uintptr
	xCurrentTime      uintptr
	xGetLastError     uintptr
	xCurrentTimeInt64 uintptr
	xSetSystemCall    uintptr
	xGetSystemCall    uintptr
	xNextSystemCall   uintptr
}

type sqlite3_vfs = sqlite3_vfs1
type sqlite3_syscall_ptr = uintptr

type sqlite3_mem_methods1 = struct {
	xMalloc   uintptr
	xFree     uintptr
	xRealloc  uintptr
	xSize     uintptr
	xRoundup  uintptr
	xInit     uintptr
	xShutdown uintptr
	pAppData  uintptr
}

type sqlite3_mem_methods = sqlite3_mem_methods1

type sqlite3_destructor_type = uintptr

type sqlite3_vtab1 = struct {
	pModule uintptr
	nRef    int32
	zErrMsg uintptr
}

type sqlite3_vtab = sqlite3_vtab1
type sqlite3_index_info1 = struct {
	nConstraint      int32
	aConstraint      uintptr
	nOrderBy         int32
	aOrderBy         uintptr
	aConstraintUsage uintptr
	idxNum           int32
	idxStr           uintptr
	needToFreeIdxStr int32
	orderByConsumed  int32
	_                [4]byte
	estimatedCost    float64
	estimatedRows    sqlite3_int64
	idxFlags         int32
	_                [4]byte
	colUsed          sqlite3_uint64
}

type sqlite3_index_info = sqlite3_index_info1
type sqlite3_vtab_cursor1 = struct{ pVtab uintptr }

type sqlite3_vtab_cursor = sqlite3_vtab_cursor1
type sqlite3_module1 = struct {
	iVersion      int32
	xCreate       uintptr
	xConnect      uintptr
	xBestIndex    uintptr
	xDisconnect   uintptr
	xDestroy      uintptr
	xOpen         uintptr
	xClose        uintptr
	xFilter       uintptr
	xNext         uintptr
	xEof          uintptr
	xColumn       uintptr
	xRowid        uintptr
	xUpdate       uintptr
	xBegin        uintptr
	xSync         uintptr
	xCommit       uintptr
	xRollback     uintptr
	xFindFunction uintptr
	xRename       uintptr
	xSavepoint    uintptr
	xRelease      uintptr
	xRollbackTo   uintptr
	xShadowName   uintptr
}

type sqlite3_module = sqlite3_module1

type sqlite3_index_constraint = struct {
	iColumn     int32
	op          uint8
	usable      uint8
	_           [2]byte
	iTermOffset int32
}

type sqlite3_index_orderby = struct {
	iColumn int32
	desc    uint8
	_       [3]byte
}

type sqlite3_index_constraint_usage = struct {
	argvIndex int32
	omit      uint8
	_         [3]byte
}

type sqlite3_mutex_methods1 = struct {
	xMutexInit    uintptr
	xMutexEnd     uintptr
	xMutexAlloc   uintptr
	xMutexFree    uintptr
	xMutexEnter   uintptr
	xMutexTry     uintptr
	xMutexLeave   uintptr
	xMutexHeld    uintptr
	xMutexNotheld uintptr
}

type sqlite3_mutex_methods = sqlite3_mutex_methods1

type sqlite3_pcache_page1 = struct {
	pBuf   uintptr
	pExtra uintptr
}

type sqlite3_pcache_page = sqlite3_pcache_page1

type sqlite3_pcache_methods21 = struct {
	iVersion   int32
	pArg       uintptr
	xInit      uintptr
	xShutdown  uintptr
	xCreate    uintptr
	xCachesize uintptr
	xPagecount uintptr
	xFetch     uintptr
	xUnpin     uintptr
	xRekey     uintptr
	xTruncate  uintptr
	xDestroy   uintptr
	xShrink    uintptr
}

type sqlite3_pcache_methods2 = sqlite3_pcache_methods21

type sqlite3_pcache_methods1 = struct {
	pArg       uintptr
	xInit      uintptr
	xShutdown  uintptr
	xCreate    uintptr
	xCachesize uintptr
	xPagecount uintptr
	xFetch     uintptr
	xUnpin     uintptr
	xRekey     uintptr
	xTruncate  uintptr
	xDestroy   uintptr
}

type sqlite3_pcache_methods = sqlite3_pcache_methods1

type sqlite3_snapshot1 = struct{ hidden [48]uint8 }

type sqlite3_snapshot = sqlite3_snapshot1

type sqlite3_rtree_geometry1 = struct {
	pContext uintptr
	nParam   int32
	aParam   uintptr
	pUser    uintptr
	xDelUser uintptr
}

type sqlite3_rtree_geometry = sqlite3_rtree_geometry1
type sqlite3_rtree_query_info1 = struct {
	pContext      uintptr
	nParam        int32
	aParam        uintptr
	pUser         uintptr
	xDelUser      uintptr
	aCoord        uintptr
	anQueue       uintptr
	nCoord        int32
	iLevel        int32
	mxLevel       int32
	iRowid        sqlite3_int64
	rParentScore  sqlite3_rtree_dbl
	eParentWithin int32
	eWithin       int32
	rScore        sqlite3_rtree_dbl
	apSqlParam    uintptr
	_             [4]byte
}

type sqlite3_rtree_query_info = sqlite3_rtree_query_info1

type sqlite3_rtree_dbl = float64

type Fts5ExtensionApi1 = struct {
	iVersion           int32
	xUserData          uintptr
	xColumnCount       uintptr
	xRowCount          uintptr
	xColumnTotalSize   uintptr
	xTokenize          uintptr
	xPhraseCount       uintptr
	xPhraseSize        uintptr
	xInstCount         uintptr
	xInst              uintptr
	xRowid             uintptr
	xColumnText        uintptr
	xColumnSize        uintptr
	xQueryPhrase       uintptr
	xSetAuxdata        uintptr
	xGetAuxdata        uintptr
	xPhraseFirst       uintptr
	xPhraseNext        uintptr
	xPhraseFirstColumn uintptr
	xPhraseNextColumn  uintptr
}

type Fts5ExtensionApi = Fts5ExtensionApi1
type Fts5PhraseIter1 = struct {
	a uintptr
	b uintptr
}

type Fts5PhraseIter = Fts5PhraseIter1

type fts5_extension_function = uintptr
type fts5_tokenizer1 = struct {
	xCreate   uintptr
	xDelete   uintptr
	xTokenize uintptr
}

type fts5_tokenizer = fts5_tokenizer1

type fts5_api1 = struct {
	iVersion         int32
	xCreateTokenizer uintptr
	xFindTokenizer   uintptr
	xCreateFunction  uintptr
}

type fts5_api = fts5_api1

type locale_t = uintptr

type ssize_t = int32

type rsize_t = size_t

type errno_t = int32
type pthread_once = struct {
	state int32
	mutex pthread_mutex_t
}

type pthread_t = uintptr
type pthread_attr_t = uintptr
type pthread_mutex_t = uintptr
type pthread_mutexattr_t = uintptr
type pthread_cond_t = uintptr
type pthread_condattr_t = uintptr
type pthread_key_t = int32
type pthread_once_t = pthread_once
type pthread_rwlock_t = uintptr
type pthread_rwlockattr_t = uintptr
type pthread_barrier_t = uintptr
type pthread_barrierattr_t = uintptr
type pthread_spinlock_t = uintptr

type pthread_addr_t = uintptr
type pthread_startroutine_t = uintptr

type u_char = uint8
type u_short = uint16
type u_int = uint32
type u_long = uint32
type ushort = uint16
type uint = uint32

type int8_t = int8

type int16_t = int16

type int32_t = int32

type int64_t = int64

type uint8_t = uint8

type uint16_t = uint16

type uint32_t = uint32

type uint64_t = uint64

type intptr_t = int32
type uintptr_t = uint32
type intmax_t = int64
type uintmax_t = uint64

type u_int8_t = uint8
type u_int16_t = uint16
type u_int32_t = uint32
type u_int64_t = uint64

type u_quad_t = uint64
type quad_t = int64
type qaddr_t = uintptr

type caddr_t = uintptr
type c_caddr_t = uintptr

type blksize_t = int32

type cpuwhich_t = int32
type cpulevel_t = int32
type cpusetid_t = int32

type blkcnt_t = int64

type clock_t = uint32

type clockid_t = int32

type critical_t = int32
type daddr_t = int64

type dev_t = uint64

type fflags_t = uint32

type fixpt_t = uint32

type fsblkcnt_t = uint64
type fsfilcnt_t = uint64

type gid_t = uint32

type in_addr_t = uint32

type in_port_t = uint16

type id_t = int64

type ino_t = uint64

type key_t = int32

type lwpid_t = int32

type mode_t = uint16

type accmode_t = int32

type nlink_t = uint64

type off_t = int64

type off64_t = int64

type pid_t = int32

type register_t = int32

type rlim_t = int64

type sbintime_t = int64

type segsz_t = int32

type suseconds_t = int32

type time_t = int64

type timer_t = uintptr

type mqd_t = uintptr

type u_register_t = uint32

type uid_t = uint32

type useconds_t = uint32

type cap_ioctl_t = uint32

type kpaddr_t = uint64
type kvaddr_t = uint64
type ksize_t = uint64
type kssize_t = int64

type vm_offset_t = uint32
type vm_ooffset_t = uint64
type vm_paddr_t = uint32
type vm_pindex_t = uint64
type vm_size_t = uint32

type rman_res_t = uint64

func __bitcount32(tls *libc.TLS, _x uint32) uint32 {
	_x = _x&uint32(0x55555555) + _x&0xaaaaaaaa>>1
	_x = _x&uint32(0x33333333) + _x&0xcccccccc>>2
	_x = (_x + _x>>4) & uint32(0x0f0f0f0f)
	_x = _x + _x>>8
	_x = (_x + _x>>16) & uint32(0x000000ff)
	return _x
}

type __sigset = struct{ __bits [4]uint32 }

type timeval = struct {
	tv_sec  time_t
	tv_usec suseconds_t
	_       [4]byte
}

type timespec = struct {
	tv_sec  time_t
	tv_nsec int32
	_       [4]byte
}

type itimerspec = struct {
	it_interval struct {
		tv_sec  time_t
		tv_nsec int32
		_       [4]byte
	}
	it_value struct {
		tv_sec  time_t
		tv_nsec int32
		_       [4]byte
	}
}

type fd_mask = uint32

type sigset_t = __sigset

type fd_set1 = struct{ __fds_bits [32]uint32 }

type fd_set = fd_set1

type timezone = struct {
	tz_minuteswest int32
	tz_dsttime     int32
}

type bintime = struct {
	sec  time_t
	frac uint64_t
}

func sbttons(tls *libc.TLS, _sbt sbintime_t) int64_t {
	var ns uint64_t

	ns = uint64_t(_sbt)
	if ns >= uint64(int64(1)<<32) {
		ns = ns >> 32 * uint64(1000000000)
	} else {
		ns = uint64(0)
	}

	return int64_t(ns + uint64_t(int64(1000000000)*(_sbt&int64(0xffffffff))>>32))
}

func nstosbt(tls *libc.TLS, _ns int64_t) sbintime_t {
	var sb sbintime_t = int64(0)

	if _ns >= int64(1000000000) {
		sb = _ns / int64(1000000000) * (int64(1) << 32)
		_ns = _ns % int64(1000000000)
	}

	sb = sbintime_t(uint64(sb) + (uint64(_ns)*9223372037+uint64(0x7fffffff))>>31)
	return sb
}

func sbttous(tls *libc.TLS, _sbt sbintime_t) int64_t {
	return int64(1000000) * _sbt >> 32
}

func ustosbt(tls *libc.TLS, _us int64_t) sbintime_t {
	var sb sbintime_t = int64(0)

	if _us >= int64(1000000) {
		sb = _us / int64(1000000) * (int64(1) << 32)
		_us = _us % int64(1000000)
	}

	sb = sbintime_t(uint64(sb) + (uint64(_us)*9223372036855+uint64(0x7fffffff))>>31)
	return sb
}

type itimerval = struct {
	it_interval struct {
		tv_sec  time_t
		tv_usec suseconds_t
		_       [4]byte
	}
	it_value struct {
		tv_sec  time_t
		tv_usec suseconds_t
		_       [4]byte
	}
}

type clockinfo = struct {
	hz     int32
	tick   int32
	spare  int32
	stathz int32
	profhz int32
}

type tm = struct {
	tm_sec    int32
	tm_min    int32
	tm_hour   int32
	tm_mday   int32
	tm_mon    int32
	tm_year   int32
	tm_wday   int32
	tm_yday   int32
	tm_isdst  int32
	tm_gmtoff int32
	tm_zone   uintptr
}

type sigevent = struct {
	sigev_notify int32
	sigev_signo  int32
	sigev_value  struct{ sival_int int32 }
	_sigev_un    struct {
		_threadid int32
		_         [28]byte
	}
}

type stat = struct {
	st_dev      dev_t
	st_ino      ino_t
	st_nlink    nlink_t
	st_mode     mode_t
	st_padding0 int16
	st_uid      uid_t
	st_gid      gid_t
	st_padding1 int32
	st_rdev     dev_t
	st_atim     struct {
		tv_sec  time_t
		tv_nsec int32
		_       [4]byte
	}
	st_mtim struct {
		tv_sec  time_t
		tv_nsec int32
		_       [4]byte
	}
	st_ctim struct {
		tv_sec  time_t
		tv_nsec int32
		_       [4]byte
	}
	st_birthtim struct {
		tv_sec  time_t
		tv_nsec int32
		_       [4]byte
	}
	st_size    off_t
	st_blocks  blkcnt_t
	st_blksize blksize_t
	st_flags   fflags_t
	st_gen     uint64
	st_spare   [10]uint64
}

type flock = struct {
	l_start  off_t
	l_len    off_t
	l_pid    pid_t
	l_type   int16
	l_whence int16
	l_sysid  int32
	_        [4]byte
}

type __oflock = struct {
	l_start  off_t
	l_len    off_t
	l_pid    pid_t
	l_type   int16
	l_whence int16
}

type xfile = struct {
	xf_size        ksize_t
	xf_pid         pid_t
	xf_uid         uid_t
	xf_fd          int32
	_xf_int_pad1   int32
	xf_file        kvaddr_t
	xf_type        int16
	_xf_short_pad1 int16
	xf_count       int32
	xf_msgcount    int32
	_xf_int_pad2   int32
	xf_offset      off_t
	xf_data        kvaddr_t
	xf_vnode       kvaddr_t
	xf_flag        u_int
	_xf_int_pad3   int32
	_xf_int64_pad  [6]int64_t
}

type sig_atomic_t = int32

type sigcontext = struct{ _dummy int32 }

type sigval = struct{ sival_int int32 }

type __siginfo = struct {
	si_signo  int32
	si_errno  int32
	si_code   int32
	si_pid    int32
	si_uid    uint32
	si_status int32
	si_addr   uintptr
	si_value  struct{ sival_int int32 }
	_reason   struct {
		_fault struct{ _trapno int32 }
		_      [28]byte
	}
}

type siginfo_t = __siginfo

type sigaction = struct {
	__sigaction_u struct{ __sa_handler uintptr }
	sa_flags      int32
	sa_mask       sigset_t
}

type sig_t = uintptr

type sigaltstack = struct {
	ss_sp    uintptr
	ss_size  uint32
	ss_flags int32
}

type stack_t = sigaltstack

type sigvec = struct {
	sv_handler uintptr
	sv_mask    int32
	sv_flags   int32
}

type sigstack = struct {
	ss_sp      uintptr
	ss_onstack int32
}

type crypt_data = struct {
	initialized int32
	__buf       [256]uint8
}

type VFSFile1 = struct {
	base        sqlite3_file
	fsFile      uintptr
	fd          int32
	aBuffer     uintptr
	nBuffer     int32
	_           [4]byte
	iBufferOfst sqlite3_int64
}

type VFSFile = VFSFile1

func vfsDirectWrite(tls *libc.TLS, p uintptr, zBuf uintptr, iAmt int32, iOfst sqlite_int64) int32 {
	bp := tls.Alloc(16)
	defer tls.Free(16)

	var ofst off_t
	var nWrite size_t

	libc.X__builtin_printf(tls, ts, libc.VaList(bp, uintptr(unsafe.Pointer(&__func__)), 178))
	libc.X__builtin_abort(tls)
	ofst = libc.Xlseek(tls, (*VFSFile)(unsafe.Pointer(p)).fd, iOfst, 0)
	if ofst != iOfst {
		return 10 | int32(3)<<8
	}

	nWrite = size_t(libc.Xwrite(tls, (*VFSFile)(unsafe.Pointer(p)).fd, zBuf, uint32(iAmt)))
	if nWrite != size_t(iAmt) {
		return 10 | int32(3)<<8
	}

	return 0
}

var __func__ = *(*[15]uint8)(unsafe.Pointer(ts + 13))

func vfsFlushBuffer(tls *libc.TLS, p uintptr) int32 {
	bp := tls.Alloc(16)
	defer tls.Free(16)

	libc.X__builtin_printf(tls, ts, libc.VaList(bp, uintptr(unsafe.Pointer(&__func__1)), 198))
	libc.X__builtin_abort(tls)
	var rc int32 = 0
	if (*VFSFile)(unsafe.Pointer(p)).nBuffer != 0 {
		rc = vfsDirectWrite(tls, p, (*VFSFile)(unsafe.Pointer(p)).aBuffer, (*VFSFile)(unsafe.Pointer(p)).nBuffer, (*VFSFile)(unsafe.Pointer(p)).iBufferOfst)
		(*VFSFile)(unsafe.Pointer(p)).nBuffer = 0
	}
	return rc
}

var __func__1 = *(*[15]uint8)(unsafe.Pointer(ts + 28))

func vfsWrite(tls *libc.TLS, pFile uintptr, zBuf uintptr, iAmt int32, iOfst sqlite_int64) int32 {
	bp := tls.Alloc(16)
	defer tls.Free(16)

	libc.X__builtin_printf(tls, ts, libc.VaList(bp, uintptr(unsafe.Pointer(&__func__4)), 273))
	libc.X__builtin_abort(tls)
	var p uintptr = pFile

	if (*VFSFile)(unsafe.Pointer(p)).aBuffer != 0 {
		var z uintptr = zBuf
		var n int32 = iAmt
		var i sqlite3_int64 = iOfst

		for n > 0 {
			var nCopy int32

			if (*VFSFile)(unsafe.Pointer(p)).nBuffer == 8192 || (*VFSFile)(unsafe.Pointer(p)).iBufferOfst+sqlite3_int64((*VFSFile)(unsafe.Pointer(p)).nBuffer) != i {
				var rc int32 = vfsFlushBuffer(tls, p)
				if rc != 0 {
					return rc
				}
			}
			if !((*VFSFile)(unsafe.Pointer(p)).nBuffer == 0 || (*VFSFile)(unsafe.Pointer(p)).iBufferOfst+sqlite3_int64((*VFSFile)(unsafe.Pointer(p)).nBuffer) == i) {
				libc.X__assert(tls, uintptr(unsafe.Pointer(&__func__4)), ts+43, 294, ts+51)
			}
			(*VFSFile)(unsafe.Pointer(p)).iBufferOfst = i - sqlite3_int64((*VFSFile)(unsafe.Pointer(p)).nBuffer)

			nCopy = 8192 - (*VFSFile)(unsafe.Pointer(p)).nBuffer
			if nCopy > n {
				nCopy = n
			}
			libc.Xmemcpy(tls, (*VFSFile)(unsafe.Pointer(p)).aBuffer+uintptr((*VFSFile)(unsafe.Pointer(p)).nBuffer), z, uint32(nCopy))
			*(*int32)(unsafe.Pointer(p + 16)) += nCopy

			n = n - nCopy
			i = i + sqlite3_int64(nCopy)
			z += uintptr(nCopy)
		}
	} else {
		return vfsDirectWrite(tls, p, zBuf, iAmt, iOfst)
	}

	return 0
}

var __func__4 = *(*[9]uint8)(unsafe.Pointer(ts + 97))

func vfsTruncate(tls *libc.TLS, pFile uintptr, size sqlite_int64) int32 {
	return 0
}

func vfsSync(tls *libc.TLS, pFile uintptr, flags int32) int32 {
	bp := tls.Alloc(16)
	defer tls.Free(16)

	libc.X__builtin_printf(tls, ts, libc.VaList(bp, uintptr(unsafe.Pointer(&__func__5)), 331))
	libc.X__builtin_abort(tls)
	var p uintptr = pFile
	var rc int32

	rc = vfsFlushBuffer(tls, p)
	if rc != 0 {
		return rc
	}

	rc = libc.Xfsync(tls, (*VFSFile)(unsafe.Pointer(p)).fd)
	return func() int32 {
		if rc == 0 {
			return 0
		}
		return 10 | int32(4)<<8
	}()
}

var __func__5 = *(*[8]uint8)(unsafe.Pointer(ts + 106))

func vfsLock(tls *libc.TLS, pFile uintptr, eLock int32) int32 {
	return 0
}

func vfsUnlock(tls *libc.TLS, pFile uintptr, eLock int32) int32 {
	return 0
}

func vfsCheckReservedLock(tls *libc.TLS, pFile uintptr, pResOut uintptr) int32 {
	*(*int32)(unsafe.Pointer(pResOut)) = 0
	return 0
}

func vfsFileControl(tls *libc.TLS, pFile uintptr, op int32, pArg uintptr) int32 {
	return 12
}

func vfsSectorSize(tls *libc.TLS, pFile uintptr) int32 {
	return 0
}

func vfsDeviceCharacteristics(tls *libc.TLS, pFile uintptr) int32 {
	return 0
}

func vfsDelete(tls *libc.TLS, pVfs uintptr, zPath uintptr, dirSync int32) int32 {
	bp := tls.Alloc(4129)
	defer tls.Free(4129)

	libc.X__builtin_printf(tls, ts, libc.VaList(bp, uintptr(unsafe.Pointer(&__func__8)), 473))
	libc.X__builtin_abort(tls)
	var rc int32

	rc = libc.Xunlink(tls, zPath)
	if rc != 0 && *(*int32)(unsafe.Pointer(libc.X__error(tls))) == 2 {
		return 0
	}

	if rc == 0 && dirSync != 0 {
		var dfd int32
		var i int32

		sqlite3.Xsqlite3_snprintf(tls, 4096, bp+32, ts+114, libc.VaList(bp+16, zPath))
		*(*uint8)(unsafe.Pointer(bp + 32 + 4096)) = uint8(0)
		for i = int32(libc.Xstrlen(tls, bp+32)); i > 1 && int32(*(*uint8)(unsafe.Pointer(bp + 32 + uintptr(i)))) != '/'; i++ {
		}
		*(*uint8)(unsafe.Pointer(bp + 32 + uintptr(i))) = uint8(0)

		dfd = libc.Xopen(tls, bp+32, 0x0000, libc.VaList(bp+24, 0))
		if dfd < 0 {
			rc = -1
		} else {
			rc = libc.Xfsync(tls, dfd)
			libc.Xclose(tls, dfd)
		}
	}
	return func() int32 {
		if rc == 0 {
			return 0
		}
		return 10 | int32(10)<<8
	}()
}

var __func__8 = *(*[10]uint8)(unsafe.Pointer(ts + 117))

func vfsDlOpen(tls *libc.TLS, pVfs uintptr, zPath uintptr) uintptr {
	return uintptr(0)
}

func vfsDlError(tls *libc.TLS, pVfs uintptr, nByte int32, zErrMsg uintptr) {
	sqlite3.Xsqlite3_snprintf(tls, nByte, zErrMsg, ts+127, 0)
	*(*uint8)(unsafe.Pointer(zErrMsg + uintptr(nByte-1))) = uint8(0)
}

func vfsDlSym(tls *libc.TLS, pVfs uintptr, pH uintptr, z uintptr) uintptr {
	return uintptr(0)
}

func vfsDlClose(tls *libc.TLS, pVfs uintptr, pHandle uintptr) {
	return
}

func vfsRandomness(tls *libc.TLS, pVfs uintptr, nByte int32, zByte uintptr) int32 {
	return 0
}

func vfsSleep(tls *libc.TLS, pVfs uintptr, nMicro int32) int32 {
	libc.Xsleep(tls, uint32(nMicro/1000000))
	libc.Xusleep(tls, uint32(nMicro%1000000))
	return nMicro
}

func vfsCurrentTime(tls *libc.TLS, pVfs uintptr, pTime uintptr) int32 {
	var t time_t = libc.Xtime(tls, uintptr(0))
	*(*float64)(unsafe.Pointer(pTime)) = float64(t)/86400.0 + 2440587.5
	return 0
}

func Xsqlite3_fsFS(tls *libc.TLS, zName uintptr, pAppData uintptr) uintptr {
	var p uintptr = sqlite3.Xsqlite3_malloc(tls, int32(unsafe.Sizeof(sqlite3_vfs{})))
	if !(p != 0) {
		return uintptr(0)
	}

	*(*sqlite3_vfs)(unsafe.Pointer(p)) = sqlite3_vfs{
		iVersion:   1,
		szOsFile:   int32(unsafe.Sizeof(VFSFile{})),
		mxPathname: 4096,
		zName:      zName,
		pAppData:   pAppData,
		xOpen: *(*uintptr)(unsafe.Pointer(&struct {
			f func(*libc.TLS, uintptr, uintptr, uintptr, int32, uintptr) int32
		}{vfsOpen})),
		xDelete: *(*uintptr)(unsafe.Pointer(&struct {
			f func(*libc.TLS, uintptr, uintptr, int32) int32
		}{vfsDelete})),
		xAccess: *(*uintptr)(unsafe.Pointer(&struct {
			f func(*libc.TLS, uintptr, uintptr, int32, uintptr) int32
		}{vfsAccess})),
		xFullPathname: *(*uintptr)(unsafe.Pointer(&struct {
			f func(*libc.TLS, uintptr, uintptr, int32, uintptr) int32
		}{vfsFullPathname})),
		xDlOpen: *(*uintptr)(unsafe.Pointer(&struct {
			f func(*libc.TLS, uintptr, uintptr) uintptr
		}{vfsDlOpen})),
		xDlError: *(*uintptr)(unsafe.Pointer(&struct {
			f func(*libc.TLS, uintptr, int32, uintptr)
		}{vfsDlError})),
		xDlSym: *(*uintptr)(unsafe.Pointer(&struct {
			f func(*libc.TLS, uintptr, uintptr, uintptr) uintptr
		}{vfsDlSym})),
		xDlClose: *(*uintptr)(unsafe.Pointer(&struct {
			f func(*libc.TLS, uintptr, uintptr)
		}{vfsDlClose})),
		xRandomness: *(*uintptr)(unsafe.Pointer(&struct {
			f func(*libc.TLS, uintptr, int32, uintptr) int32
		}{vfsRandomness})),
		xSleep: *(*uintptr)(unsafe.Pointer(&struct {
			f func(*libc.TLS, uintptr, int32) int32
		}{vfsSleep})),
		xCurrentTime: *(*uintptr)(unsafe.Pointer(&struct {
			f func(*libc.TLS, uintptr, uintptr) int32
		}{vfsCurrentTime}))}
	return p
}

var ts1 = "TODO %s:%i:\n\x00vfsDirectWrite\x00vfsFlushBuffer\x00c/vfs.c\x00p->nBuffer==0 || p->iBufferOfst+p->nBuffer==i\x00vfsWrite\x00vfsSync\x00%s\x00vfsDelete\x00Loadable extensions are not supported\x00"
var ts = (*reflect.StringHeader)(unsafe.Pointer(&ts1)).Data
