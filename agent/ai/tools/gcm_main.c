// SPDX-License-Identifier: GPL-2.0
/*
 * gcm_main.c - aik-gcm：corpus 包加密面（DATA-L1-DESIGN §3 棒③）
 *
 * 独立小二进制（沿 aik-compat 先例：-ffunction-sections -fdata-sections
 * + -Wl,--gc-sections，链 third_party/mbedtls/library/libmbedcrypto.a；
 * 裁剪配置 include/mbedtls/mbedtls-trim.h B7 批 GCM/CTR/CTR_DRBG 保留，
 * 见该文件 101-102 行注释）。纯字节面无路径逻辑：stdin→stdout。
 *
 * 包格式（versioned，小端）：
 *
 *   off  0   8B   magic "AIKCORP1"（ASCII）
 *   off  8   2B   version u16（现值 1）
 *   off 10  32B   key_ref 定长串字段（NUL 填充；现值 "keyfile:corpus.key"
 *                 ——设计 §0：key_ref 入包格式，后续升 keyring/TPM 不破
 *                 坏旧包）
 *   off 42  12B   nonce（CTR_DRBG 随机；AES-GCM 标准 96bit）
 *   off 54  16B   tag（128bit）
 *   off 70  ..    ciphertext（AES-256-GCM，key=--key 文件 32B）
 *   AAD = 包头自身 [0,54)（magic+ver+key_ref+nonce——tag 前的全部字节；
 *   头被篡改=tag 必败）
 *
 * 子命令：
 *   aik-gcm enc  --key F [--key-ref S] [--nonce HEX]
 *       stdin 明文 → stdout 包。--nonce 12B hex 仅诊断/向量复现用
 *       （GCM nonce 同 key 下必须唯一——生产路径恒 CTR_DRBG 随机）。
 *   aik-gcm dec  --key F
 *       stdin 包 → stdout 明文。tag 校验失败绝不输出半明文（先整包
 *       auth_decrypt 成功再写 stdout）。
 *   aik-gcm keygen --key F
 *       mbedtls CTR_DRBG 生成 32B，O_EXCL 写 0600（已存在=拒绝，绝不
 *       静默覆盖既有密钥）。设计 §0：/var/lib/aikernel/corpus.key。
 *   aik-gcm selftest
 *       内跑三组公开 NIST/McGrew-Viega AES-256-GCM 测试向量（零 AAD
 *       裸 GCM 面；包面 AAD=包头由 enc/dec 往返覆盖）。
 *
 * key 文件契约：普通文件、恰 32B、权限 0600（group/other 可读=拒绝——
 * corpus 密钥姿态，人话报错指路 chmod 600）。
 *
 * 退出码：0 成功；1 用法错；2 key 文件错（缺失/长度/权限/keygen 已存
 * 在）；3 坏包（magic/version/长度/key_ref 字段形状）；4 tag 校验失败
 * （数据或包头被篡改/错 key）；5 I/O 错。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mbedtls/gcm.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#define PKG_MAGIC	"AIKCORP1"	/* 8B */
#define PKG_MAGIC_LEN	8
#define PKG_VERSION	1
#define KEYREF_FIELD	32		/* 定长 NUL 填充串字段 */
#define NONCE_LEN	12
#define TAG_LEN		16
#define KEY_LEN		32		/* AES-256 */
#define HDR_LEN		(PKG_MAGIC_LEN + 2 + KEYREF_FIELD + NONCE_LEN)
			/* 54B：AAD 覆盖到 tag 前 */
#define PKG_FIXED	(HDR_LEN + TAG_LEN)	/* 70B：密文前固定前缀 */

#define DEFAULT_KEY_REF	"keyfile:corpus.key"

#define RC_OK		0
#define RC_USAGE	1
#define RC_KEY		2
#define RC_PACKAGE	3
#define RC_TAMPER	4
#define RC_IO		5

/* NIST/McGrew-Viega GCM spec 测试向量（AES-256，公开已知；AAD 空）。
 * selftest 内逐组 mbedtls_gcm_crypt_and_tag 对拍 ct+tag。 */
struct gcm_vector {
	const char *name;
	const char *key_hex;	/* 64 hex = 32B */
	const char *iv_hex;	/* 24 hex = 12B */
	const char *pt_hex;	/* 可空串 */
	const char *ct_hex;
	const char *tag_hex;	/* 32 hex = 16B */
};

static const struct gcm_vector vectors[] = {
	{ "NIST-GCM-256-TC1",
	  "00000000000000000000000000000000"
	  "00000000000000000000000000000000",
	  "000000000000000000000000",
	  "",
	  "",
	  "530f8afbc74536b9a963b4f1c4cb738b" },
	{ "NIST-GCM-256-TC2",
	  "00000000000000000000000000000000"
	  "00000000000000000000000000000000",
	  "000000000000000000000000",
	  "00000000000000000000000000000000",
	  "cea7403d4d606b6e074ec5d3baf39d18",
	  "d0d1c8a799996bf0265b98b5d48ab919" },
	{ "NIST-GCM-256-TC3",
	  "feffe9928665731c6d6a8f9467308308"
	  "feffe9928665731c6d6a8f9467308308",
	  "cafebabefacedbaddecaf888",
	  "d9313225f88406e5a55909c5aff5269a"
	  "86a7a9531534f7da2e4c303d8a318a72"
	  "1c3c0c95956809532fcf0e2449a6b525"
	  "b16aedf5aa0de657ba637b391aafd255",
	  "522dc1f099567d07f47f37a32a84427d"
	  "643a8cdcbfe5c0c97598a2bd2555d1aa"
	  "8cb08e48590dbb3da7b08b1056828838"
	  "c5f61e6393ba7a0abcc9f662898015ad",
	  "b094dac5d93471bdec1a502270e3cc6c" },
};

static int hex_val(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* hex → bytes；长度非法/非 hex 字符返回 -1 */
static int unhex(const char *hex, unsigned char *out, size_t out_cap,
		 size_t *out_len)
{
	size_t n = strlen(hex), i;

	if (n % 2 || n / 2 > out_cap)
		return -1;
	for (i = 0; i < n; i += 2) {
		int hi = hex_val(hex[i]), lo = hex_val(hex[i + 1]);

		if (hi < 0 || lo < 0)
			return -1;
		out[i / 2] = (unsigned char)((hi << 4) | lo);
	}
	*out_len = n / 2;
	return 0;
}

static void *xmalloc(size_t n)
{
	void *p = malloc(n ? n : 1);

	if (!p) {
		fprintf(stderr, "aik-gcm: out of memory (%zu bytes)\n", n);
		exit(RC_IO);
	}
	return p;
}

/* 读整个 fd，产出 buf 与 len（空输入= len 0，buf 恒非 NULL 便于 free） */
static int read_all(int fd, unsigned char **buf, size_t *len)
{
	size_t cap = 1u << 16, n = 0;
	unsigned char *p = xmalloc(cap);

	for (;;) {
		ssize_t r;

		if (n == cap) {
			unsigned char *q;

			if (cap > (size_t)1 << 31) {
				free(p);
				return -1;
			}
			cap *= 2;
			q = realloc(p, cap);
			if (!q) {
				free(p);
				return -1;
			}
			p = q;
		}
		r = read(fd, p + n, cap - n);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			free(p);
			return -1;
		}
		if (r == 0)
			break;
		n += (size_t)r;
	}
	*buf = p;
	*len = n;
	return 0;
}

/* key 文件读取：普通文件+恰 32B+0600（group/other 位必须空） */
static int load_key(const char *path, unsigned char key[KEY_LEN])
{
	FILE *f;
	struct stat st;
	size_t n;

	f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "aik-gcm: 无法打开 key 文件 %s: %s\n",
			path, strerror(errno));
		return RC_KEY;
	}
	if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode)) {
		fprintf(stderr, "aik-gcm: key 文件 %s 不是普通文件\n", path);
		fclose(f);
		return RC_KEY;
	}
	if (st.st_size != KEY_LEN) {
		fprintf(stderr,
			"aik-gcm: key 文件 %s 长度 %lld 错（需恰 %d 字节，"
			"AES-256）\n", path, (long long)st.st_size, KEY_LEN);
		fclose(f);
		return RC_KEY;
	}
	if (st.st_mode & (S_IRWXG | S_IRWXO)) {
		fprintf(stderr,
			"aik-gcm: key 文件 %s 权限过宽（%04o，需 0600）——"
			"先 chmod 600 %s\n", path,
			(unsigned)(st.st_mode & 07777), path);
		fclose(f);
		return RC_KEY;
	}
	n = fread(key, 1, KEY_LEN, f);
	if (n != KEY_LEN) {
		fprintf(stderr, "aik-gcm: key 文件 %s 读取不完整\n", path);
		fclose(f);
		return RC_KEY;
	}
	fclose(f);
	return RC_OK;
}

static int cmd_keygen(const char *path)
{
	mbedtls_entropy_context ent;
	mbedtls_ctr_drbg_context drbg;
	unsigned char key[KEY_LEN];
	int fd, rc;
	struct stat st;

	if (stat(path, &st) == 0) {
		fprintf(stderr,
			"aik-gcm: keygen 拒绝——%s 已存在（绝不静默覆盖既有"
			"密钥；确要重置先手动 rm）\n", path);
		return RC_KEY;
	}
	mbedtls_entropy_init(&ent);
	mbedtls_ctr_drbg_init(&drbg);
	rc = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent,
				   NULL, 0);
	if (rc != 0) {
		fprintf(stderr, "aik-gcm: CTR_DRBG 播种失败 -0x%04x\n", -rc);
		mbedtls_ctr_drbg_free(&drbg);
		mbedtls_entropy_free(&ent);
		return RC_IO;
	}
	rc = mbedtls_ctr_drbg_random(&drbg, key, sizeof(key));
	mbedtls_ctr_drbg_free(&drbg);
	mbedtls_entropy_free(&ent);
	if (rc != 0) {
		fprintf(stderr, "aik-gcm: CTR_DRBG 取随机失败 -0x%04x\n",
			-rc);
		return RC_IO;
	}
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		fprintf(stderr, "aik-gcm: 创建 %s 失败: %s\n", path,
			strerror(errno));
		return RC_IO;
	}
	if (write(fd, key, sizeof(key)) != (ssize_t)sizeof(key)) {
		fprintf(stderr, "aik-gcm: 写 %s 失败: %s\n", path,
			strerror(errno));
		close(fd);
		unlink(path);
		return RC_IO;
	}
	close(fd);
	printf("aik-gcm: keygen 已写 %s（32B，0600）\n", path);
	return RC_OK;
}

static int cmd_enc(const char *key_path, const char *key_ref,
		   const char *nonce_hex)
{
	unsigned char key[KEY_LEN];
	unsigned char nonce[NONCE_LEN];
	unsigned char tag[TAG_LEN];
	unsigned char *pt = NULL, *ct, header[HDR_LEN];
	size_t pt_len = 0;
	mbedtls_gcm_context gcm;
	mbedtls_entropy_context ent;
	mbedtls_ctr_drbg_context drbg;
	int rc, krc;
	size_t kr_len, i;

	krc = load_key(key_path, key);
	if (krc != RC_OK)
		return krc;
	if (read_all(STDIN_FILENO, &pt, &pt_len) != 0) {
		fprintf(stderr, "aik-gcm: 读 stdin 失败: %s\n",
			strerror(errno));
		free(pt);
		return RC_IO;
	}
	if (nonce_hex) {
		size_t nlen = 0;

		if (unhex(nonce_hex, nonce, sizeof(nonce), &nlen) != 0 ||
		    nlen != NONCE_LEN) {
			fprintf(stderr,
				"aik-gcm: --nonce 需恰 %d 字节 hex（24 字符）"
				"——仅诊断/向量复现用\n", NONCE_LEN);
			free(pt);
			return RC_USAGE;
		}
	} else {
		mbedtls_entropy_init(&ent);
		mbedtls_ctr_drbg_init(&drbg);
		rc = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func,
					   &ent, NULL, 0);
		if (rc == 0)
			rc = mbedtls_ctr_drbg_random(&drbg, nonce,
						     sizeof(nonce));
		mbedtls_ctr_drbg_free(&drbg);
		mbedtls_entropy_free(&ent);
		if (rc != 0) {
			fprintf(stderr,
				"aik-gcm: nonce 随机源失败 -0x%04x\n", -rc);
			free(pt);
			return RC_IO;
		}
	}
	kr_len = strlen(key_ref);
	if (kr_len == 0 || kr_len >= KEYREF_FIELD) {
		fprintf(stderr,
			"aik-gcm: key_ref 长度 %zu 非法（需 1..%d 字节）\n",
			kr_len, KEYREF_FIELD - 1);
		free(pt);
		return RC_USAGE;
	}
	memset(header, 0, sizeof(header));
	memcpy(header, PKG_MAGIC, PKG_MAGIC_LEN);
	header[PKG_MAGIC_LEN] = PKG_VERSION & 0xff;
	header[PKG_MAGIC_LEN + 1] = (PKG_VERSION >> 8) & 0xff;
	memcpy(header + PKG_MAGIC_LEN + 2, key_ref, kr_len);
	memcpy(header + PKG_MAGIC_LEN + 2 + KEYREF_FIELD, nonce, NONCE_LEN);

	ct = xmalloc(pt_len ? pt_len : 1);
	mbedtls_gcm_init(&gcm);
	rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
	if (rc == 0)
		rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
					       pt_len, nonce, NONCE_LEN,
					       header, HDR_LEN, pt, ct,
					       TAG_LEN, tag);
	mbedtls_gcm_free(&gcm);
	if (rc != 0) {
		fprintf(stderr, "aik-gcm: AES-256-GCM 加密失败 -0x%04x\n",
			-rc);
		free(pt);
		free(ct);
		return RC_IO;
	}
	/* 包 = header(54) | tag(16) | ciphertext */
	if (write(STDOUT_FILENO, header, HDR_LEN) != (ssize_t)HDR_LEN ||
	    write(STDOUT_FILENO, tag, TAG_LEN) != (ssize_t)TAG_LEN) {
		fprintf(stderr, "aik-gcm: 写 stdout 失败: %s\n",
			strerror(errno));
		rc = RC_IO;
	} else if (pt_len &&
		   write(STDOUT_FILENO, ct, pt_len) != (ssize_t)pt_len) {
		fprintf(stderr, "aik-gcm: 写 stdout 失败: %s\n",
			strerror(errno));
		rc = RC_IO;
	} else {
		rc = RC_OK;
	}
	/* 密钥材料擦除 */
	memset(key, 0, sizeof(key));
	for (i = 0; i < pt_len; i++)
		pt[i] = 0;
	free(pt);
	free(ct);
	return rc;
}

static int cmd_dec(const char *key_path)
{
	unsigned char key[KEY_LEN];
	unsigned char *in = NULL, *pt;
	size_t in_len = 0;
	const unsigned char *nonce, *tag, *ct;
	size_t ct_len;
	mbedtls_gcm_context gcm;
	int rc, krc, ret = RC_OK;

	krc = load_key(key_path, key);
	if (krc != RC_OK)
		return krc;
	if (read_all(STDIN_FILENO, &in, &in_len) != 0) {
		fprintf(stderr, "aik-gcm: 读 stdin 失败: %s\n",
			strerror(errno));
		return RC_IO;
	}
	if (in_len < PKG_FIXED) {
		fprintf(stderr,
			"aik-gcm: 坏包——输入 %zu 字节短于固定包头 %d 字节"
			"（不是 aikcorp 包？）\n", in_len, PKG_FIXED);
		free(in);
		return RC_PACKAGE;
	}
	if (memcmp(in, PKG_MAGIC, PKG_MAGIC_LEN) != 0) {
		fprintf(stderr,
			"aik-gcm: 坏包——magic 不符（前 8 字节非 "
			"\"AIKCORP1\"；不是 aikcorp 包或已损坏）\n");
		free(in);
		return RC_PACKAGE;
	}
	{
		unsigned ver = in[PKG_MAGIC_LEN] |
			       ((unsigned)in[PKG_MAGIC_LEN + 1] << 8);

		if (ver != PKG_VERSION) {
			fprintf(stderr,
				"aik-gcm: 坏包——版本 %u 不受支持（本程序 "
				"支持版本 %d）\n", ver, PKG_VERSION);
			free(in);
			return RC_PACKAGE;
		}
	}
	/* key_ref 定长字段必须含 NUL（NUL 填充形状校验） */
	if (memchr(in + PKG_MAGIC_LEN + 2, '\0', KEYREF_FIELD) == NULL) {
		fprintf(stderr,
			"aik-gcm: 坏包——key_ref 字段无 NUL 终止（字段形状"
			"非法）\n");
		free(in);
		return RC_PACKAGE;
	}
	nonce = in + PKG_MAGIC_LEN + 2 + KEYREF_FIELD;
	tag = in + HDR_LEN;
	ct = in + PKG_FIXED;
	ct_len = in_len - PKG_FIXED;
	pt = xmalloc(ct_len ? ct_len : 1);
	mbedtls_gcm_init(&gcm);
	rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
	if (rc == 0)
		rc = mbedtls_gcm_auth_decrypt(&gcm, ct_len, nonce, NONCE_LEN,
					      in, HDR_LEN, tag, TAG_LEN,
					      ct, pt);
	mbedtls_gcm_free(&gcm);
	memset(key, 0, sizeof(key));
	if (rc == MBEDTLS_ERR_GCM_AUTH_FAILED) {
		fprintf(stderr,
			"aik-gcm: tag 校验失败——数据或包头已被篡改，或 "
			"key 不对；明文绝不输出（半明文=泄漏）\n");
		free(in);
		free(pt);
		return RC_TAMPER;
	}
	if (rc != 0) {
		fprintf(stderr, "aik-gcm: 解密失败 -0x%04x\n", -rc);
		free(in);
		free(pt);
		return RC_IO;
	}
	if (ct_len &&
	    write(STDOUT_FILENO, pt, ct_len) != (ssize_t)ct_len) {
		fprintf(stderr, "aik-gcm: 写 stdout 失败: %s\n",
			strerror(errno));
		ret = RC_IO;
	}
	free(in);
	free(pt);
	return ret;
}

static int cmd_selftest(void)
{
	int i, fail = 0;

	for (i = 0; i < (int)(sizeof(vectors) / sizeof(vectors[0])); i++) {
		const struct gcm_vector *v = &vectors[i];
		unsigned char key[KEY_LEN], iv[NONCE_LEN], tag[TAG_LEN];
		unsigned char *pt = xmalloc(strlen(v->pt_hex) / 2 + 1);
		unsigned char *ct_exp = xmalloc(strlen(v->ct_hex) / 2 + 1);
		unsigned char *ct_got = xmalloc(strlen(v->ct_hex) / 2 + 1);
		unsigned char tag_exp[TAG_LEN];
		size_t kl, il, pl, cl, tl;
		mbedtls_gcm_context gcm;
		int rc, ok = 1;

		if (unhex(v->key_hex, key, sizeof(key), &kl) != 0 ||
		    unhex(v->iv_hex, iv, sizeof(iv), &il) != 0 ||
		    unhex(v->pt_hex, pt, strlen(v->pt_hex) / 2 + 1, &pl) != 0 ||
		    unhex(v->ct_hex, ct_exp, strlen(v->ct_hex) / 2 + 1,
			  &cl) != 0 ||
		    unhex(v->tag_hex, tag_exp, sizeof(tag_exp), &tl) != 0 ||
		    kl != KEY_LEN || il != NONCE_LEN || tl != TAG_LEN) {
			printf("  %-18s FAIL（测试向量解析错误——程序数据"
			       "损坏？）\n", v->name);
			fail++;
			goto vnext;
		}
		mbedtls_gcm_init(&gcm);
		rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key,
					256);
		if (rc == 0)
			rc = mbedtls_gcm_crypt_and_tag(&gcm,
						       MBEDTLS_GCM_ENCRYPT,
						       pl, iv, NONCE_LEN,
						       NULL, 0, pt, ct_got,
						       TAG_LEN, tag);
		mbedtls_gcm_free(&gcm);
		if (rc != 0 || cl != pl ||
		    (cl && memcmp(ct_got, ct_exp, cl) != 0) ||
		    memcmp(tag, tag_exp, TAG_LEN) != 0)
			ok = 0;
		printf("  %-18s %s\n", v->name, ok ? "PASS" : "FAIL");
		if (!ok)
			fail++;
vnext:
		free(pt);
		free(ct_exp);
		free(ct_got);
	}
	printf("GCM_SELFTEST cases=%d ok=%d\n",
	       (int)(sizeof(vectors) / sizeof(vectors[0])),
	       (int)(sizeof(vectors) / sizeof(vectors[0])) - fail);
	return fail ? RC_IO : RC_OK;
}

static void usage(FILE *out)
{
	fprintf(out,
		"用法：aik-gcm <子命令> [选项]（corpus 包加密面，stdin→stdout）\n"
		"  aik-gcm enc --key F [--key-ref S] [--nonce HEX]\n"
		"      stdin 明文 → stdout 加密包（AES-256-GCM；包格式见源码头注）\n"
		"  aik-gcm dec --key F\n"
		"      stdin 加密包 → stdout 明文（tag 败=退出码 4，零输出）\n"
		"  aik-gcm keygen --key F\n"
		"      生成 32B 密钥写 0600（已存在=拒绝）\n"
		"  aik-gcm selftest\n"
		"      三组公开 NIST AES-256-GCM 测试向量\n"
		"退出码：0 成功 1 用法 2 key 文件 3 坏包 4 tag 败(篡改) 5 I/O\n");
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(stderr);
		return RC_USAGE;
	}
	if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
		usage(stdout);
		return RC_OK;
	}
	if (strcmp(argv[1], "selftest") == 0 && argc == 2)
		return cmd_selftest();
	if (strcmp(argv[1], "keygen") == 0 && argc == 4 &&
	    strcmp(argv[2], "--key") == 0)
		return cmd_keygen(argv[3]);
	if (strcmp(argv[1], "enc") == 0 && argc >= 4) {
		const char *key = NULL, *key_ref = DEFAULT_KEY_REF;
		const char *nonce = NULL;
		int i;

		for (i = 2; i < argc; i += 2) {
			if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
				key = argv[i + 1];
			else if (strcmp(argv[i], "--key-ref") == 0 &&
				 i + 1 < argc)
				key_ref = argv[i + 1];
			else if (strcmp(argv[i], "--nonce") == 0 &&
				 i + 1 < argc)
				nonce = argv[i + 1];
			else
				break;
		}
		if (key && i >= argc)
			return cmd_enc(key, key_ref, nonce);
	} else if (strcmp(argv[1], "dec") == 0 && argc == 4 &&
		   strcmp(argv[2], "--key") == 0) {
		return cmd_dec(argv[3]);
	}
	usage(stderr);
	return RC_USAGE;
}
