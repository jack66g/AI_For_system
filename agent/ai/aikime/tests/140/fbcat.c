/* fbcat — /dev/fb0 抓屏器（P-55 集成验收）
 * 用法：fbcat [-o out.ppm] [-s y0 y1]
 * 输出：stdout「xres yres bpp nonblack=N」（y0..y1 行段内非黑像素计数，
 * 亮度阈值 16）；-o 另存 PPM 存证。
 * 140 无 gcc：L1 gcc -static 编译后 scp。 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/fb.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	const char *out = NULL;
	int y0 = -1, y1 = -1;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[++i];
		else if (!strcmp(argv[i], "-s") && i + 2 < argc) {
			y0 = atoi(argv[++i]);
			y1 = atoi(argv[++i]);
		}
	}

	int fd = open("/dev/fb0", O_RDONLY);
	if (fd < 0) { perror("open /dev/fb0"); return 1; }

	struct fb_var_screeninfo vi;
	struct fb_fix_screeninfo fi;
	if (ioctl(fd, FBIOGET_VSCREENINFO, &vi) < 0 ||
	    ioctl(fd, FBIOGET_FSCREENINFO, &fi) < 0) {
		perror("FBIOGET"); return 1;
	}

	size_t fbw = (size_t)vi.xres * vi.yres * (vi.bits_per_pixel / 8);
	unsigned char *buf = malloc(fbw);
	if (!buf) return 1;
	if (pread(fd, buf, fbw, 0) != (ssize_t)fbw) { perror("read fb"); return 1; }
	close(fd);

	if (y0 < 0) { y0 = 0; y1 = (int)vi.yres; }
	if (y1 > (int)vi.yres) y1 = (int)vi.yres;

	long nonblack = 0;
	for (int y = y0; y < y1; y++) {
		for (unsigned x = 0; x < vi.xres; x++) {
			unsigned char r, g, b;
			unsigned char *p = buf + ((size_t)y * vi.xres + x) * (vi.bits_per_pixel / 8);
			if (vi.bits_per_pixel == 32) {
				b = p[0]; g = p[1]; r = p[2];
			} else if (vi.bits_per_pixel == 16) {
				unsigned short v;
				memcpy(&v, p, 2);
				r = (unsigned char)((v >> 11) & 0x1f) * 8;
				g = (unsigned char)((v >> 5) & 0x3f) * 4;
				b = (unsigned char)(v & 0x1f) * 8;
			} else if (vi.bits_per_pixel == 24) {
				b = p[0]; g = p[1]; r = p[2];
			} else {
				fprintf(stderr, "bpp %u unsupported\n", vi.bits_per_pixel);
				return 1;
			}
			if ((r + g + b) / 3 > 16) nonblack++;
		}
	}

	if (out) {
		FILE *f = fopen(out, "wb");
		if (f) {
			fprintf(f, "P6\n%u %u\n255\n", vi.xres, vi.yres);
			for (unsigned y = 0; y < vi.yres; y++) {
				for (unsigned x = 0; x < vi.xres; x++) {
					unsigned char rgb[3];
					unsigned char *p = buf + ((size_t)y * vi.xres + x) * (vi.bits_per_pixel / 8);
					if (vi.bits_per_pixel == 32) {
						rgb[2] = p[0]; rgb[1] = p[1]; rgb[0] = p[2];
					} else if (vi.bits_per_pixel == 16) {
						unsigned short v;
						memcpy(&v, p, 2);
						rgb[0] = (unsigned char)((v >> 11) & 0x1f) * 8;
						rgb[1] = (unsigned char)((v >> 5) & 0x3f) * 4;
						rgb[2] = (unsigned char)(v & 0x1f) * 8;
					} else {
						rgb[2] = p[0]; rgb[1] = p[1]; rgb[0] = p[2];
					}
					fwrite(rgb, 1, 3, f);
				}
			}
			fclose(f);
		}
	}

	printf("%u %u %u nonblack=%ld rows=%d-%d\n",
	       vi.xres, vi.yres, vi.bits_per_pixel, nonblack, y0, y1);
	return 0;
}
