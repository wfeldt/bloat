#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>	/* BLKGETSIZE64 */
#include <x86emu.h>


#define FIRST_DISK	0x80
#define FIRST_CDROM	0xe0
#define MAX_DISKS	0x100


typedef struct {
  unsigned type;
  unsigned boot:1;
  unsigned valid:1;
  struct {
    unsigned c, h, s, lin;
  } start;
  struct {
    unsigned c, h, s, lin;
  } end;
  unsigned base;
} ptable_t;


typedef struct {
  x86emu_t *emu;

  unsigned kbd_cnt;
  unsigned key;

  unsigned memsize;	// in MB

  unsigned a20:1;

  struct {
    unsigned iv_base;
    int (* iv_funcs[0x100])(x86emu_t *emu);
  } bios;
} vm_t;


void lprintf(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
void flush_log(char *buf, unsigned size);

void help(void);
void handle_int(x86emu_t *emu, unsigned nr);
int check_ip(x86emu_t *emu);
vm_t *vm_new(void);
void vm_free(vm_t *vm);
void vm_run(vm_t *vm);
unsigned cs2s(unsigned cs);
unsigned cs2c(unsigned cs);
int do_int(x86emu_t *emu, u8 num, unsigned type);
int do_int_10(x86emu_t *emu);
int do_int_11(x86emu_t *emu);
int do_int_12(x86emu_t *emu);
int do_int_13(x86emu_t *emu);
int do_int_15(x86emu_t *emu);
int do_int_16(x86emu_t *emu);
int do_int_19(x86emu_t *emu);
void prepare_bios(vm_t *vm);
void prepare_boot(x86emu_mem_t *mem);
int disk_read(x86emu_mem_t *vm, unsigned addr, unsigned disk, uint64_t sector, unsigned cnt, int log);
void parse_ptable(x86emu_mem_t *vm, unsigned addr, ptable_t *ptable, unsigned base, unsigned ext_base, int entries);
int guess_geo(ptable_t *ptable, int entries, unsigned *s, unsigned *h);
void print_ptable_entry(int nr, ptable_t *ptable);
int is_ext_ptable(ptable_t *ptable);
ptable_t *find_ext_ptable(ptable_t *ptable, int entries);
void dump_ptable(x86emu_mem_t *vm, unsigned disk);
char *get_screen(x86emu_mem_t *vm);
void dump_screen(x86emu_mem_t *vm);


struct option options[] = {
  { "help",       0, NULL, 'h'  },
  { "verbose",    0, NULL, 'v'  },
  { "disk",       1, NULL, 1001 },
  { "floppy",     1, NULL, 1002 },
  { "cdrom",      1, NULL, 1003 },
  { "boot",       1, NULL, 1004 },
  { "show",       1, NULL, 1005 },
  { "no-show",    1, NULL, 1006 },
  { "feature",    1, NULL, 1007 },
  { "no-feature", 1, NULL, 1008 },
  { "max",        1, NULL, 1009 },
  { "log-size",   1, NULL, 1010 },
  { }
};

struct {
  unsigned verbose;
  unsigned inst_max;
  unsigned log_size; 

  struct {
    char *dev;
    int fd;
    unsigned heads;
    unsigned sectors;
    unsigned cylinders;
    uint64_t size;
  } disk[MAX_DISKS];

  unsigned floppies;
  unsigned disks;
  unsigned cdroms;
  unsigned boot;

  struct {
    unsigned code:1;
    unsigned regs:1;
    unsigned data:1;
    unsigned io:1;
    unsigned ints:1;
    unsigned acc:1;
    unsigned rawptable:1;
    unsigned dump:1;
    unsigned dumpmem:1;
    unsigned dumpattr:1;
    unsigned dumpregs:1;
    unsigned dumpio:1;
    unsigned dumpints:1;
  } show;

  struct {
    unsigned edd:1;
  } feature;
} opt;


FILE *log_file = NULL;

int main(int argc, char **argv)
{
  char *s, *t, *dev_spec, *err_msg = NULL;
  int i, j, err;
  unsigned u, u2, ofs, *uu;
  struct stat sbuf;
  uint64_t ul;
  ptable_t ptable[4];
  x86emu_mem_t *vm_0 = x86emu_mem_new(X86EMU_PERM_R | X86EMU_PERM_W);
  vm_t *vm;

  log_file = stdout;

  opt.inst_max = 100000;
  opt.feature.edd = 1;

  opterr = 0;

  while((i = getopt_long(argc, argv, "hv", options, NULL)) != -1) {
    err = 0;
    dev_spec = NULL;

    switch(i) {
      case 'v':
        opt.verbose++;
        break;

      case 1001:
      case 1002:
      case 1003:
        if(i == 1001) {
          if(opt.disks >= FIRST_CDROM - FIRST_DISK) break;
          uu = &opt.disks;
          ofs = FIRST_DISK + opt.disks;
        }
        else if(i == 1002) {
          if(opt.floppies >= FIRST_DISK) break;
          uu = &opt.floppies;
          ofs = opt.floppies;
        }
        else /* i == 1003 */ {
          if(opt.cdroms >= MAX_DISKS - FIRST_CDROM) break;
          uu = &opt.cdroms;
          ofs = FIRST_CDROM + opt.cdroms;
        }

        dev_spec = strdup(optarg);
        if((s = strchr(dev_spec, ','))) {
          *s++ = 0;
        }
        if(!*dev_spec) {
          err = 1;
          break;
        }
        opt.disk[ofs].dev = strdup(dev_spec);
        if(s) {
          u = strtoul(s, &t, 0);
          if((*t == 0 || *t == ',') && u <= 255) {
            opt.disk[ofs].heads = u;
          }
          else {
            err = 2;
            break;
          }
          if(*t++ == ',') {
            u = strtoul(t, &t, 0);
            if(*t == 0 && u <= 63) {
              opt.disk[ofs].sectors = u;
            }
            else {
              err = 3;
              break;
            }
          }
        }
        (*uu)++;
        break;

      case 1004:
        if(!strcmp(optarg, "floppy")) {
          opt.boot = 0;
        }
        else if(!strcmp(optarg, "disk")) {
          opt.boot = FIRST_DISK;
        }
        else if(!strcmp(optarg, "cdrom")) {
          opt.boot = FIRST_CDROM;
        }
        else {
          u = strtoul(optarg, &s, 0);
          if(s != optarg && !*s && u < MAX_DISKS) {
            opt.boot = u;
          }
          else {
            err = 4;
          }
        }
        break;

      case 1005:
      case 1006:
        s = optarg;
        u = i == 1005 ? 1 : 0;
        while((t = strsep(&s, ","))) {
          if(!strcmp(t, "code")) opt.show.code = u;
          else if(!strcmp(t, "regs")) opt.show.regs = u;
          else if(!strcmp(t, "data")) opt.show.data = u;
          else if(!strcmp(t, "io")) opt.show.io = u;
          else if(!strcmp(t, "ints")) opt.show.ints = u;
          else if(!strcmp(t, "acc")) opt.show.acc = u;
          else if(!strcmp(t, "rawptable")) opt.show.rawptable = u;
          else if(!strcmp(t, "dump")) opt.show.dump = u;
          else if(!strcmp(t, "dump.mem")) opt.show.dumpmem = u;
          else if(!strcmp(t, "dump.attr")) opt.show.dumpattr = u;
          else if(!strcmp(t, "dump.regs")) opt.show.dumpregs = u;
          else if(!strcmp(t, "dump.io")) opt.show.dumpio = u;
          else if(!strcmp(t, "dump.ints")) opt.show.dumpints = u;
          else {
            err_msg = t;
            err = 5;
          }
        }
        break;

      case 1007:
      case 1008:
        s = optarg;
        u = i == 1007 ? 1 : 0;
        while((t = strsep(&s, ","))) {
          if(!strcmp(t, "edd")) opt.feature.edd = u;
          else err = 6;
        }
        break;

      case 1009:
        opt.inst_max = strtoul(optarg, NULL, 0);
        break;

      case 1010:
        opt.log_size = strtoul(optarg, NULL, 0);
        break;

      default:
        help();
        return i == 'h' ? 0 : 1;
    }

    free(dev_spec);

    if(err && (i == 1001 || i == 1002 || i == 1003)) {
      fprintf(stderr, "invalid device spec: %s\n", optarg);
      return 1;
    }

    if(err && i == 1004) {
      fprintf(stderr, "invalid boot device: %s\n", optarg);
      return 1;
    }

    if(err && (i == 1005 || i == 1006)) {
      fprintf(stderr, "invalid show spec: %s\n", err_msg);
      return 1;
    }

    if(err && (i == 1007 || i == 1008)) {
      fprintf(stderr, "invalid feature: %s\n", optarg);
      return 1;
    }
  }

  if(!opt.disks && !opt.floppies && !opt.cdroms) {
    fprintf(stderr, "we need some drives\n");
    return 1;
  }

  if(!opt.disk[opt.boot].dev) {
    if(opt.disk[FIRST_CDROM].dev) {
      opt.boot = FIRST_CDROM;
    }
    else if(opt.disk[FIRST_DISK].dev) {
      opt.boot = FIRST_DISK;
    }
    else if(opt.disk[0].dev) {
      opt.boot = 0;
    }
  }

  printf("drive map:\n");

  for(i = 0; i < MAX_DISKS; i++) {
    opt.disk[i].fd = -1;
    if(!opt.disk[i].dev) continue;

    opt.disk[i].fd = open(opt.disk[i].dev, O_RDONLY | O_LARGEFILE);
    if(opt.disk[i].fd < 0) continue;

    if(!opt.disk[i].heads || !opt.disk[i].sectors) {
      j = disk_read(vm_0, 0, i, 0, 1, 0);
      if(!j && vm_read_word(vm_0, 0x1fe) == 0xaa55) {
        parse_ptable(vm_0, 0x1be, ptable, 0, 0, 4);
        if(guess_geo(ptable, 4, &u, &u2)) {
          if(!opt.disk[i].sectors) opt.disk[i].sectors = u;
          if(!opt.disk[i].heads) opt.disk[i].heads = u2;
        }
      }
    }

    if(!opt.disk[i].heads) opt.disk[i].heads = 255;
    if(!opt.disk[i].sectors) opt.disk[i].sectors = 63;

    ul = 0;
    if(!fstat(opt.disk[i].fd, &sbuf)) ul = sbuf.st_size;
    if(!ul && ioctl(opt.disk[i].fd, BLKGETSIZE64, &ul)) ul = 0;
    opt.disk[i].size = ul >> 9;
    opt.disk[i].cylinders = opt.disk[i].size / (opt.disk[i].sectors * opt.disk[i].heads);

    printf("  0x%02x: %s, chs %u/%u/%u, %llu sectors\n",
      i,
      opt.disk[i].dev,
      opt.disk[i].cylinders,
      opt.disk[i].heads,
      opt.disk[i].sectors,
      (unsigned long long) opt.disk[i].size
     );

    dump_ptable(vm_0, i);
  }

  printf("boot device: 0x%02x\n", opt.boot);

  fflush(stdout);

  vm = vm_new();

  prepare_bios(vm);

  prepare_boot(vm->emu->mem);

  vm_run(vm);

  dump_screen(vm->emu->mem);

  return 0;
}


void lprintf(const char *format, ...)
{
  va_list args;

  va_start(args, format);
  if(log_file) vfprintf(log_file, format, args);
  va_end(args);
}


void flush_log(char *buf, unsigned size)
{
  if(!buf || !size || !log_file) return;

  fwrite(buf, size, 1, log_file);
}


void help()
{
  fprintf(stderr,
    "Boot Loader Test\nusage: bloat options\n"
    "  --boot DEVICE\n"
    "      boot from DEVICE\n"
    "      DEVICE is either a number (0-0xff) or one of: floppy, disk, cdrom\n"
    "  --disk device[,heads,sectors]\n"
    "      add hard disk image [with geometry]\n"
    "  --floppy device[,heads,sectors]\n"
    "      add floppy disk image [with geometry]\n"
    "  --cdrom device[,heads,sectors]\n"
    "      add cdrom image [with geometry]\n"
    "  --show LIST\n"
    "      things to log\n"
    "      LIST is a comma-separated list of: code, regs, data, io, acc, rawptable,\n"
    "      dump, dump.mem, dump.attr, dump.regs\n"
    "  --no-show LIST\n"
    "      things not to log (see --show)\n"
    "  --feature LIST\n"
    "      features to enable\n"
    "      LIST is a comma-separated list of: edd\n"
    "  --no-feature LIST\n"
    "      features to disable (see --features)\n"
    "  --max N\n"
    "      stop after N instructions\n"
    "  --log-size N\n"
    "      internal log buffer size\n"
    "  --help\n"
    "      show this text\n"
    "examples:\n"
    "  bloat --floppy floppy.img --disk /dev/sda --disk foo.img --boot floppy\n"
    "  bloat --disk linux.img\n"
    "  bloat --cdrom foo.iso --show code,regs\n"
  );
}


unsigned cs2s(unsigned cs)
{
  return cs & 0x3f;
}


unsigned cs2c(unsigned cs)
{
  return ((cs >> 8) & 0xff) + ((cs & 0xc0) << 2);
}


int check_ip(x86emu_t *emu)
{
  vm_t *vm = emu->private;
  unsigned u;

  u = emu->x86.R_CS_BASE + emu->x86.R_EIP;

  if(u >= vm->bios.iv_base && u < vm->bios.iv_base + 0x100) {
    handle_int(emu, u - vm->bios.iv_base);
  }

  return 0;
}


void handle_int(x86emu_t *emu, unsigned nr)
{
  vm_t *vm = emu->private;
  x86emu_mem_t *mem = emu->mem;
  int stop = 0;
  u8 flags;

  if(!vm->bios.iv_funcs[nr]) {
    x86emu_log(emu, "# unhandled interrupt 0x%02x\n", nr);
    stop = 1;
  }
  else {
    stop = vm->bios.iv_funcs[nr](emu);
    flags = emu->x86.R_FLG;
    vm_write_byte(mem, emu->x86.R_SS_BASE + ((emu->x86.R_SP + 4) & 0xffff), flags);
  }

  if(stop) x86emu_stop(emu);
}


int do_int(x86emu_t *emu, u8 num, unsigned type)
{
  vm_t *vm = emu->private;

  if((type & 0xff) == INTR_TYPE_FAULT) {
    x86emu_stop(emu);

    return 0;
  }

  if(vm->bios.iv_funcs[num]) return 0;

  x86emu_log(emu, "# unhandled interrupt 0x%02x\n", num);

  return 1;
}


int do_int_10(x86emu_t *emu)
{
  x86emu_mem_t *mem = x86emu.mem;
  unsigned u, cnt, attr;
  unsigned cur_x, cur_y, page;
  unsigned x, y, x0, y0, x1, y1, width, d;

  switch(x86emu.x86.R_AH) {
    case 0x01:
      printf("int 0x10: ah 0x%02x (set cursor shape)\n", x86emu.x86.R_AH);
      // x86emu.x86.R_CX: shape
      break;

    case 0x02:
      printf("int 0x10: ah 0x%02x (set cursor)\n", x86emu.x86.R_AH);
      printf("(x, y) = (%u, %u)\n", x86emu.x86.R_DL, x86emu.x86.R_DH);
      page = x86emu.x86.R_BH & 7;
      vm_write_byte(mem, 0x450 + 2 * page, x86emu.x86.R_DL);	// x
      vm_write_byte(mem, 0x451 + 2 * page, x86emu.x86.R_DH);	// y
      break;

    case 0x03:
      printf("int 0x10: ah 0x%02x (get cursor)\n", x86emu.x86.R_AH);
      page = x86emu.x86.R_BH & 7;
      x86emu.x86.R_DL = vm_read_byte(mem, 0x450 + 2 * page);	// x
      x86emu.x86.R_DH = vm_read_byte(mem, 0x451 + 2 * page);	// y
      x86emu.x86.R_CX = 0x607;					// cursor shape
      printf("(x, y) = (%u, %u)\n", x86emu.x86.R_DL, x86emu.x86.R_DH);
      break;

    case 0x06:
      printf("int 0x10: ah 0x%02x (scroll up)\n", x86emu.x86.R_AH);
      attr = 0x20 + (x86emu.x86.R_BH << 8);
      x0 = x86emu.x86.R_CL;
      y0 = x86emu.x86.R_CH;
      x1 = x86emu.x86.R_DL;
      y1 = x86emu.x86.R_DH;
      d = x86emu.x86.R_AL;
      printf("  window (%u, %u) - (%u, %u), by %u lines\n", x0, y0, x1, y1, d);
      width = vm_read_byte(mem, 0x44a);
      if(x0 > width) x0 = width;
      if(x1 > width) x1 = width;
      u = vm_read_byte(mem, 0x484);
      if(y0 > u) y0 = u;
      if(y1 > u) y1 = u;
      if(y1 > y0 && x1 > x0) {
        if(d == 0) {
          for(y = y0; y <= y1; y++) {
            for(x = x0; x < x1; x++) {
              vm_write_word(mem, 0xb8000 + 2 * (x + width * y), attr);
            }
          }
        }
        else {
          for(y = y0; y < y1; y++) {
            for(x = x0; x < x1; x++) {
              u = vm_read_word(mem, 0xb8000 + 2 * (x + width * (y + 1)));
              vm_write_word(mem, 0xb8000 + 2 * (x + width * y), u);
            }
          }
          for(x = x0; x < x1; x++) {
            vm_write_word(mem, 0xb8000 + 2 * (x + width * y), attr);
          }
        }
      }
      break;

    case 0x09:
      printf("int 0x10: ah 0x%02x (write char & attr)\n", x86emu.x86.R_AH);
      u = x86emu.x86.R_AL;
      attr = x86emu.x86.R_BL;
      page = x86emu.x86.R_BH & 7;
      cnt = x86emu.x86.R_CX;
      cur_x = vm_read_byte(mem, 0x450 + 2 * page);
      cur_y = vm_read_byte(mem, 0x451 + 2 * page);
      printf("char 0x%02x '%c', attr 0x%02x, cnt %u\n", u, u >= 0x20 && u < 0x7f ? u : ' ', attr, cnt);
      while(cnt--) {
        vm_write_byte(mem, 0xb8000 + 2 * (cur_x + 80 * cur_y), u);
        vm_write_byte(mem, 0xb8001 + 2 * (cur_x + 80 * cur_y), attr);
        cur_x++;
      }
      break;

    case 0x0e:
      printf("int 0x10: ah 0x%02x (tty print)\n", x86emu.x86.R_AH);
      u = x86emu.x86.R_AL;
      page = x86emu.x86.R_BH & 7;
      cur_x = vm_read_byte(mem, 0x450 + 2 * page);
      cur_y = vm_read_byte(mem, 0x451 + 2 * page);
      printf("char 0x%02x '%c'\n", u, u >= 0x20 && u < 0x7f ? u : ' ');
      if(u == 0x0d) {
        cur_x = 0;
      }
      else if(u == 0x0a) {
        cur_y++;
      }
      else {
        vm_write_byte(mem, 0xb8000 + 2 * (cur_x + 80 * cur_y), u);
        vm_write_byte(mem, 0xb8001 + 2 * (cur_x + 80 * cur_y), 7);
        cur_x++;
        if(cur_x == 80) {
          cur_x = 0;
          cur_y++;
        }
      }
      vm_write_byte(mem, 0x450 + 2 * page, cur_x);
      vm_write_byte(mem, 0x451 + 2 * page, cur_y);
      break;

    case 0x0f:
      x86emu.x86.R_AL = vm_read_byte(mem, 0x449);	// vide mode
      x86emu.x86.R_AH = vm_read_byte(mem, 0x44a);	// screen width
      x86emu.x86.R_BH = 0;				// active page
      break;

    default:
      printf("int 0x10: ah 0x%02x\n", x86emu.x86.R_AH);
      break;
  }

  return 0;
}


int do_int_11(x86emu_t *emu)
{
  printf("int 0x11: (get equipment list)\n");
  x86emu.x86.R_AX = 0x4026;
  printf("eq mask: %04x\n", x86emu.x86.R_AX);

  return 0;
}


int do_int_12(x86emu_t *emu)
{
  x86emu_mem_t *mem = x86emu.mem;

  printf("int 0x12: (get base mem size)\n");
  x86emu.x86.R_AX = vm_read_word(mem, 0x413);
  printf("base mem size: %u kB\n", x86emu.x86.R_AX);

  return 0;
}


int do_int_13(x86emu_t *emu)
{
  x86emu_mem_t *mem = x86emu.mem;
  unsigned u, disk, cnt, sector, cylinder, head, addr;
  uint64_t ul;
  int i, j;

  switch(x86emu.x86.R_AH) {
    case 0x00:
      printf("int 0x13: ah 0x%02x (disk reset)\n", x86emu.x86.R_AH);
      disk = x86emu.x86.R_DL;
      printf("drive 0x%02x\n", disk);
      if(disk >= MAX_DISKS || !opt.disk[disk].dev) {
        x86emu.x86.R_AH = 7;
        SET_FLAG(F_CF);
      }
      else {
        x86emu.x86.R_AH = 0;
        CLEAR_FLAG(F_CF);
      }
      break;

    case 0x02:
      printf("int 0x13: ah 0x%02x (disk read)\n", x86emu.x86.R_AH);
      disk = x86emu.x86.R_DL;
      cnt = x86emu.x86.R_AL;
      head = x86emu.x86.R_DH;
      cylinder = cs2c(x86emu.x86.R_CX);
      sector = cs2s(x86emu.x86.R_CX);
      addr = (x86emu.x86.R_ES << 4) + x86emu.x86.R_BX;
      printf("drive 0x%02x, chs %u/%u/%u, %u sectors, buf 0x%05x\n",
        disk,
        cylinder, head, sector,
        cnt,
        addr
      );
      if(cnt) {
        if(!sector) {
          x86emu.x86.R_AH = 0x04;
          SET_FLAG(F_CF);
          break;
        }
        ul = (cylinder * opt.disk[disk].heads + head) * opt.disk[disk].sectors + sector - 1;
        i = disk_read(mem, addr, disk, ul, cnt, 1);
        if(i) {
          x86emu.x86.R_AH = 0x04;
          SET_FLAG(F_CF);
          break;
        }
      }      
      x86emu.x86.R_AH = 0;
      CLEAR_FLAG(F_CF);
      break;

    case 0x08:
      printf("int 0x13: ah 0x%02x (get drive params)\n", x86emu.x86.R_AH);
      disk = x86emu.x86.R_DL;
      printf("drive 0x%02x\n", disk);
      if(
        disk >= MAX_DISKS ||
        !opt.disk[disk].dev ||
        !opt.disk[disk].sectors ||
        !opt.disk[disk].heads
      ) {
        x86emu.x86.R_AH = 0x07;
        SET_FLAG(F_CF);
        break;
      }
      CLEAR_FLAG(F_CF);
      x86emu.x86.R_AH = 0;
      x86emu.x86.R_ES = 0;
      x86emu.x86.R_DI = 0;
      x86emu.x86.R_BL = 0;
      x86emu.x86.R_DL = disk < 0x80 ? opt.floppies : opt.disks;
      x86emu.x86.R_DH = opt.disk[disk].heads - 1;
      u = opt.disk[disk].cylinders;
      if(u > 1023) u = 1023;
      x86emu.x86.R_CX = ((u >> 8) << 6) + ((u & 0xff) << 8) + opt.disk[disk].sectors;
      break;

    case 0x41:
      printf("int 0x13: ah 0x%02x (edd install check)\n", x86emu.x86.R_AH);
      disk = x86emu.x86.R_DL;
      printf("drive 0x%02x\n", disk);
      if(!opt.feature.edd || disk >= MAX_DISKS || !opt.disk[disk].dev || x86emu.x86.R_BX != 0x55aa) {
        x86emu.x86.R_AH = 1;
        SET_FLAG(F_CF);
      }
      else {
        x86emu.x86.R_AX = 0x3000;
        x86emu.x86.R_BX = 0xaa55;
        x86emu.x86.R_CX = 0x000f;
        CLEAR_FLAG(F_CF);
      }
      break;

    case 0x42:
      printf("int 0x13: ah 0x%02x (edd disk read)\n", x86emu.x86.R_AH);
      disk = x86emu.x86.R_DL;
      addr = (x86emu.x86.R_DS << 4) + x86emu.x86.R_SI;
      printf("drive 0x%02x, request packet:\n0x%05x: ", disk, addr);
      j = vm_read_byte(mem, addr);
      j = j == 0x10 || j == 0x18 ? j : 0x10;
      for(i = 0; i < j; i++) {
        printf("%02x%c", vm_read_byte(mem, addr + i), i == j - 1 ? '\n' : ' ');
      }
      if(
        !opt.feature.edd || disk >= MAX_DISKS || !opt.disk[disk].dev ||
        (vm_read_byte(mem, addr) != 0x10 && vm_read_byte(mem, addr) != 0x18)
      ) {
        x86emu.x86.R_AH = 1;
        SET_FLAG(F_CF);
        break;
      }
      cnt = vm_read_word(mem, addr + 2);
      u = vm_read_dword(mem, addr + 4);
      ul = vm_read_qword(mem, addr + 8);
      if(vm_read_byte(mem, addr) == 0x18 && u == 0xffffffff) {
        u = vm_read_dword(mem, addr + 0x10);
      }
      else {
        u = vm_read_segofs16(mem, addr + 4);
      }
      if(disk >= FIRST_CDROM) {
        ul <<= 2;
        cnt <<= 2;
      }
      i = disk_read(mem, u, disk, ul, cnt, 1);
      if(i) {
        x86emu.x86.R_AH = 0x04;
        SET_FLAG(F_CF);
        break;
      }
      x86emu.x86.R_AH = 0;
      CLEAR_FLAG(F_CF);
      break;

    case 0x48:
      printf("int 0x13: ax 0x%02x (get drive params)\n", x86emu.x86.R_AH);
      disk = x86emu.x86.R_DL;
      printf("drive 0x%02x\n", disk);
      if(
        disk >= MAX_DISKS ||
        !opt.disk[disk].dev ||
        !opt.disk[disk].sectors ||
        !opt.disk[disk].heads
      ) {
        x86emu.x86.R_AH = 0x07;
        SET_FLAG(F_CF);
        break;
      }
      CLEAR_FLAG(F_CF);
      x86emu.x86.R_AH = 0;

      u = x86emu.x86.R_DS_BASE + x86emu.x86.R_SI;

      vm_write_word(mem, u, 0x1a);	// buffer size
      vm_write_word(mem, u + 2, 3);
      vm_write_dword(mem, u + 4, opt.disk[disk].cylinders);
      vm_write_dword(mem, u + 8, opt.disk[disk].heads);
      vm_write_dword(mem, u + 0xc, opt.disk[disk].sectors);
      vm_write_qword(mem, u + 0x10, opt.disk[disk].size);
      vm_write_word(mem, u + 0x18, 0x200);	// sector size
      break;

    case 0x4b:
      printf("int 0x13: ax 0x%04x (terminate disk emulation)\n", x86emu.x86.R_AX);
      if(x86emu.x86.R_AL == 1) {
        x86emu.x86.R_AH = 0x01;
        SET_FLAG(F_CF);
      }
      else {
        x86emu.x86.R_AH = 0x01;
        SET_FLAG(F_CF);
      }
      break;

    default:
      printf("int 0x13: ah 0x%02x (not implemented)\n", x86emu.x86.R_AH);

      x86emu.x86.R_AH = 0x01;
      SET_FLAG(F_CF);
      break;
  }

  return 0;
}


int do_int_15(x86emu_t *emu)
{
  vm_t *vm = x86emu.private;
  x86emu_mem_t *mem = x86emu.mem;
  unsigned u, u1;

  switch(x86emu.x86.R_AH) {
    case 0x24:
      printf("int 0x15: ah 0x%02x (a20 gate)\n", x86emu.x86.R_AH);
      switch(x86emu.x86.R_AL) {
        case 0:
          vm->a20 = 0;
          printf("a20 disabled\n");
          x86emu.x86.R_AH = 0;
          CLEAR_FLAG(F_CF);
          break;

        case 1:
          vm->a20 = 1;
          printf("a20 enabled\n");
          x86emu.x86.R_AH = 0;
          CLEAR_FLAG(F_CF);
          break;

        case 2:
          printf("a20 status: %u\n", vm->a20);
          x86emu.x86.R_AH = 0;
          x86emu.x86.R_AL = vm->a20;
          CLEAR_FLAG(F_CF);
          break;

        case 3:
          printf("a20 support: 3\n");
          x86emu.x86.R_AH = 0;
          x86emu.x86.R_BX = 3;
          CLEAR_FLAG(F_CF);
          break;

        default:
          SET_FLAG(F_CF);
          break;
      }
      break;

    case 0x42:
      printf("int 0x15: ax 0x%04x (thinkpad stuff)\n", x86emu.x86.R_AX);
      // x86emu.x86.R_AX = 0x8600;	// ask for F11
      // x86emu.x86.R_AX = 1;		// start rescue
      break;

    case 0x88:
      printf("int 0x15: ah 0x%02x (ext. mem size)\n", x86emu.x86.R_AH);
      u = vm->memsize - 1;
      printf("ext mem size: %u MB\n", u);
      x86emu.x86.R_AX = u;
      CLEAR_FLAG(F_CF);
      break;

    case 0xe8:
      if(x86emu.x86.R_AL == 1) {
        printf("int 0x15: ax 0x%04x (mem map (old))\n", x86emu.x86.R_AX);
        u = vm->memsize - 1;
        u1 = 0;
        if(u > 15) {
          u = 15;
          u1 = vm->memsize - 16;
        }
        x86emu.x86.R_AX = x86emu.x86.R_CX = u << 10;
        x86emu.x86.R_BX = x86emu.x86.R_DX = u1 << 4;
        printf("ext mem sizes: %u MB + %u MB\n", u, u1);
        CLEAR_FLAG(F_CF);
      }
      if(x86emu.x86.R_AL == 0x20 && x86emu.x86.R_EDX == 0x534d4150) {
        printf("int 0x15: ax 0x%04x (mem map (new))\n", x86emu.x86.R_AX);
        u = vm->memsize;
        if(x86emu.x86.R_EBX == 0) {
          x86emu.x86.R_EAX = 0x534d4150;
          x86emu.x86.R_EBX = 0;
          x86emu.x86.R_ECX = 20;
          u1 = x86emu.x86.R_ES_BASE + x86emu.x86.R_DI;
          vm_write_qword(mem, u1, 0);
          vm_write_qword(mem, u1 + 8, (uint64_t) u << 20);
          vm_write_dword(mem, u1 + 0x10, 1);
          printf("mem size: %u MB\n", u);
          CLEAR_FLAG(F_CF);
        }
        else {
          SET_FLAG(F_CF);
        }
      }
      break;

    default:
      printf("int 0x15: ax 0x%04x\n", x86emu.x86.R_AX);
      break;
  }

  return 0;
}


int do_int_16(x86emu_t *emu)
{
  vm_t *vm = x86emu.private;
  int stop = 0;

  switch(x86emu.x86.R_AH) {
    case 0x00:
    case 0x10:
      printf("int 0x16: ah 0x%02x (get key)\n", x86emu.x86.R_AH);
      x86emu.x86.R_AX = vm->key ?: 0x1c0d;
      vm->key = 0;

#if 0
      // we should rather stop here
      printf("blocking key read - stopped\n");
      stop = 1;
#endif
      break;

    case 0x01:
    case 0x11:
      printf("int 0x16: ah 0x%02x (check for key)\n", x86emu.x86.R_AH);
      vm->kbd_cnt++;

      if(vm->kbd_cnt % 4) {
        CLEAR_FLAG(F_ZF);
        vm->key = 0x1c0d;
        x86emu.x86.R_AX = vm->key;
      }
      else {
        SET_FLAG(F_ZF);
      }
      break;

    default:
      printf("int 0x16: ah 0x%02x\n", x86emu.x86.R_AH);
      break;
  }

  return stop;
}


int do_int_19(x86emu_t *emu)
{
//  vm_t *vm = x86emu.private;

  printf("int 0x19: (boot next device)\n");

  return 1;
}


vm_t *vm_new()
{
  vm_t *vm;
  unsigned u;

  vm = calloc(1, sizeof *vm);

  vm->emu = x86emu_new(X86EMU_PERM_R | X86EMU_PERM_W | X86EMU_PERM_X, 0);
  vm->emu->private = vm;

  x86emu_set_log(vm->emu, opt.log_size ?: 10000000, flush_log);
  if(opt.show.regs) vm->emu->log.regs = 1;
  if(opt.show.code) vm->emu->log.code = 1;
  if(opt.show.data) vm->emu->log.data = 1;
  if(opt.show.acc) vm->emu->log.acc = 1;
  if(opt.show.io) vm->emu->log.io = 1;
  if(opt.show.ints) vm->emu->log.ints = 1;

  for(u = 0; u < 0x100; u++) x86emu_set_intr_func(vm->emu, u, do_int);

  x86emu_set_code_check(vm->emu, check_ip);

  return vm;
}


void vm_free(vm_t *vm)
{
  free(vm);
}


void vm_run(vm_t *vm)
{
  int flags;

  vm->emu->x86.R_DL = opt.boot;

  if(vm_read_word(vm->emu->mem, 0x7c00) == 0) return;

  flags = X86EMU_RUN_LOOP | X86EMU_RUN_NO_CODE;
  if(opt.inst_max) {
    vm->emu->max_instr = opt.inst_max;
    flags |= X86EMU_RUN_MAX_INSTR;
  }

  x86emu_run(vm->emu, flags);

  flags = 0;
  if(opt.show.dump) flags |= -1;
  if(opt.show.dumpmem) flags |= X86EMU_DUMP_MEM;
  if(opt.show.dumpattr) flags |= X86EMU_DUMP_MEM | X86EMU_DUMP_ATTR;
  if(opt.show.dumpregs) flags |= X86EMU_DUMP_REGS;
  if(opt.show.dumpio) flags |= X86EMU_DUMP_IO;
  if(opt.show.dumpints) flags |= X86EMU_DUMP_INTS;

  if(flags) {
    x86emu_log(vm->emu, "\n- - vm dump - -\n");
    x86emu_dump(vm->emu, flags);
  }

  x86emu_clear_log(vm->emu, 1);
}


void prepare_bios(vm_t *vm)
{
  unsigned u;
  x86emu_mem_t *mem = vm->emu->mem;

  vm->memsize = 1024;	// 1GB RAM

  // jmp far 0:0x7c00
  vm_write_byte(mem, 0xffff0, 0xea);
  vm_write_word(mem, 0xffff1, 0x7c00);
  vm_write_word(mem, 0xffff3, 0x0000);

  vm_write_word(mem, 0x413, 640);	// mem size in kB
  vm_write_byte(mem, 0x449, 3);		// video mode
  vm_write_byte(mem, 0x44a, 80);		// columns
  vm_write_byte(mem, 0x484, 24);		// rows - 1
  vm_write_byte(mem, 0x485, 16);		// char height
  vm_write_byte(mem, 0x462, 0);		// current text page
  vm_write_word(mem, 0x450, 0);		// page 0 cursor pos

  vm_write_dword(mem, 0x46c, 0);		// time

  vm->bios.iv_base = 0xf8000 + 0x100;
  for(u = 0; u < 0x100; u++) {
    vm_write_byte(mem, vm->bios.iv_base + u, 0xcf);	// iret
  }

  vm_write_word(mem, 0x10*4, 0x100 + 0x10);
  vm_write_word(mem, 0x10*4+2, 0xf800);
  vm->bios.iv_funcs[0x10] = do_int_10;

  vm_write_word(mem, 0x11*4, 0x100 + 0x11);
  vm_write_word(mem, 0x11*4+2, 0xf800);
  vm->bios.iv_funcs[0x11] = do_int_11;

  vm_write_word(mem, 0x12*4, 0x100 + 0x12);
  vm_write_word(mem, 0x12*4+2, 0xf800);
  vm->bios.iv_funcs[0x12] = do_int_12;

  vm_write_word(mem, 0x13*4, 0x100 + 0x13);
  vm_write_word(mem, 0x13*4+2, 0xf800);
  vm->bios.iv_funcs[0x13] = do_int_13;

  vm_write_word(mem, 0x15*4, 0x100 + 0x15);
  vm_write_word(mem, 0x15*4+2, 0xf800);
  vm->bios.iv_funcs[0x15] = do_int_15;

  vm_write_word(mem, 0x16*4, 0x100 + 0x16);
  vm_write_word(mem, 0x16*4+2, 0xf800);
  vm->bios.iv_funcs[0x16] = do_int_16;

  vm_write_word(mem, 0x19*4, 0x100 + 0x19);
  vm_write_word(mem, 0x19*4+2, 0xf800);
  vm->bios.iv_funcs[0x19] = do_int_19;
}


int el_torito_boot(x86emu_mem_t *mem, unsigned disk)
{
  unsigned char sector[2048];
  unsigned et, u;
  unsigned start, load_len, load_addr;
  int ok = 0;

  disk_read(mem, 0x7c00, disk, 0x11 * 4, 4, 1);	/* 1 sector from 0x8800 */
  for(u = 0; u < 2048; u++) {
    sector[u] = vm_read_byte_noerr(mem, 0x7c00 + u);
  }

  if(
    sector[0] == 0 && sector[6] == 1 &&
    !memcmp(sector + 1, "CD001", 5) &&
    !memcmp(sector + 7, "EL TORITO SPECIFICATION", 23)
  ) {
    et = sector[0x47] + (sector[0x48] << 8) + (sector[0x49] << 16) + (sector[0x4a] << 24);
    lprintf("el_torito_boot: boot catalog at 0x%04x\n", et);
    if(!disk_read(mem, 0x7c00, disk, et * 4, 4, 1)) {
      if(vm_read_byte_noerr(mem, 0x7c20) == 0x88) {	/* bootable */
        load_addr = vm_read_word(mem, 0x7c22) << 4;
        if(!load_addr) load_addr = 0x7c00;
        load_len = vm_read_word(mem, 0x7c26) << 9;
        start = vm_read_dword(mem, 0x7c28);

        lprintf(
          "el_torito_boot: load 0x%x bytes from sector 0x%x to 0x%x\n",
          load_len, start, load_addr
        );

        disk_read(mem, load_addr, disk, start * 4, load_len >> 9, 1);
        ok = 1;
      }
    }
  }

  return ok;
}


void prepare_boot(x86emu_mem_t *mem)
{
  if(opt.boot < FIRST_CDROM) {
    disk_read(mem, 0x7c00, opt.boot, 0, 1, 1);
  }
  else {
    el_torito_boot(mem, opt.boot);
  }
}


int disk_read(x86emu_mem_t *mem, unsigned addr, unsigned disk, uint64_t sector, unsigned cnt, int log)
{
  off_t ofs;
  unsigned char *buf;
  unsigned u;

  if(log) printf("read: disk 0x%02x, sector %llu (%u) @ 0x%05x - ",
    disk, (unsigned long long) sector, cnt, addr
  );

  if(disk >= MAX_DISKS || !opt.disk[disk].dev) {
    if(log) printf("invalid disk\n");
    return 2;
  }

  if(opt.disk[disk].fd < 0) {
    if(log) printf("failed to open disk\n");
    return 3;
  }

  ofs = sector << 9;

  if(lseek(opt.disk[disk].fd, ofs, SEEK_SET) != ofs) {
    if(log) printf("sector not found\n");
    return 4;
  }

  buf = malloc(cnt << 9);

  if(read(opt.disk[disk].fd, buf, cnt << 9) != (cnt << 9)) {
    if(log) printf("read error\n");
    free(buf);

    return 5;
  }

  for(u = 0; u < cnt << 9; u++) {
    vm_write_byte(mem, addr + u, buf[u]);
  }

  if(log) printf("ok\n");

  return 0;
}


void parse_ptable(x86emu_mem_t *mem, unsigned addr, ptable_t *ptable, unsigned base, unsigned ext_base, int entries)
{
  unsigned u;

  memset(ptable, 0, entries * sizeof *ptable);

  for(; entries; entries--, addr += 0x10, ptable++) {
    u = vm_read_byte(mem, addr);
    if(u & 0x7f) continue;
    ptable->boot = u >> 7;
    ptable->type = vm_read_byte(mem, addr + 4);
    u = vm_read_word(mem, addr + 2);
    ptable->start.c = cs2c(u);
    ptable->start.s = cs2s(u);
    ptable->start.h = vm_read_byte(mem, addr + 1);
    ptable->start.lin = vm_read_dword(mem, addr + 8);
    u = vm_read_word(mem, addr + 6);
    ptable->end.c = cs2c(u);
    ptable->end.s = cs2s(u);
    ptable->end.h = vm_read_byte(mem, addr + 5);
    ptable->end.lin = ptable->start.lin + vm_read_dword(mem, addr + 0xc);

    ptable->base = is_ext_ptable(ptable) ? ext_base : base;

    if(ptable->end.lin != ptable->start.lin && ptable->start.s && ptable->end.s) {
      ptable->valid = 1;
      ptable->end.lin--;
    }
  }
}


int guess_geo(ptable_t *ptable, int entries, unsigned *s, unsigned *h)
{
  unsigned sectors, heads, u, c;
  int i, ok, cnt;

  for(sectors = 63; sectors; sectors--) {
    for(heads = 255; heads; heads--) {
      ok = 1;
      for(cnt = i = 0; i < entries; i++) {
        if(!ptable[i].valid) continue;

        if(ptable[i].start.h >= heads) { ok = 0; break; }
        if(ptable[i].start.s > sectors) { ok = 0; break; }
        if(ptable[i].start.c >= 1023) {
          c = ((ptable[i].start.lin + 1 - ptable[i].start.s)/sectors - ptable[i].start.h)/heads;
          if(c < 1023) { ok = 0; break; }
        }
        else {
          c = ptable[i].start.c;
        }
        u = (c * heads + ptable[i].start.h) * sectors + ptable[i].start.s - 1;
        if(u != ptable[i].start.lin) {
          ok = 0;
          break;
        }
        cnt++;
        if(ptable[i].end.h >= heads) { ok = 0; break; }
        if(ptable[i].end.s > sectors) { ok = 0; break; }
        if(ptable[i].end.c >= 1023) {
          c = ((ptable[i].end.lin + 1 - ptable[i].end.s)/sectors - ptable[i].end.h)/heads;
          if(c < 1023) { ok = 0; break; }
        }
        else {
          c = ptable[i].end.c;
        }
        u = (c * heads + ptable[i].end.h) * sectors + ptable[i].end.s - 1;
        if(u != ptable[i].end.lin) {
          ok = 0;
          break;
        }
        cnt++;
      }
      if(!cnt) ok = 0;
      if(ok) break;
    }
    if(ok) break;
  }

  if(ok) {
    *h = heads;
    *s = sectors;
  }

  return ok;
}


void print_ptable_entry(int nr, ptable_t *ptable)
{
  unsigned u;

  if(ptable->valid) {
    printf("    ");
    if(nr > 4 && is_ext_ptable(ptable)) {
      printf("-");
    }
    else {
      printf("%d", nr);
    }

    u = opt.show.rawptable ? 0 : ptable->base;

    printf(": %c 0x%02x, start %4u/%3u/%2u %9u, end %4u/%3u/%2u %9u",
      ptable->boot ? '*' : ' ',
      ptable->type,
      ptable->start.c, ptable->start.h, ptable->start.s,
      ptable->start.lin + u,
      ptable->end.c, ptable->end.h, ptable->end.s,
      ptable->end.lin + u
    );

    if(opt.show.rawptable) printf(" %+9d", ptable->base);
    printf("\n");
  }
}


int is_ext_ptable(ptable_t *ptable)
{
  return ptable->type == 5 || ptable->type == 0xf;
}


ptable_t *find_ext_ptable(ptable_t *ptable, int entries)
{
  for(; entries; entries--, ptable++) {
    if(ptable->valid && is_ext_ptable(ptable)) return ptable;
  }
  return NULL;
}


void dump_ptable(x86emu_mem_t *mem, unsigned disk)
{
  int i, j, pcnt, link_count;
  ptable_t ptable[4], *ptable_ext;
  unsigned s, h, ext_base;

  i = disk_read(mem, 0, disk, 0, 1, 0);

  if(i || vm_read_word(mem, 0x1fe) != 0xaa55) {
    printf("    no partition table\n");
    return;
  }

  parse_ptable(mem, 0x1be, ptable, 0, 0, 4);
  i = guess_geo(ptable, 4, &s, &h);
  printf("    partition table (");
  if(i) {
    printf("hs %u/%u):\n", h, s);
  }
  else {
    printf("inconsistent chs):\n");
  }

  for(i = 0; i < 4; i++) {
    print_ptable_entry(i + 1, ptable + i);
  }

  pcnt = 5;

  link_count = 0;
  ext_base = 0;

  while((ptable_ext = find_ext_ptable(ptable, 4))) {
    if(!link_count++) {
      ext_base = ptable_ext->start.lin;
    }
    if(link_count > 100) {
      printf("    too many partitions\n");
      break;
    }
    j = disk_read(mem, 0, disk, ptable_ext->start.lin + ptable_ext->base, 1, 0);
    if(j || vm_read_word(mem, 0x1fe) != 0xaa55) {
      printf("    ");
      if(j) printf("disk read error - ");
      printf("not a valid extended partition\n");
      break;
    }
    parse_ptable(mem, 0x1be, ptable, ptable_ext->start.lin + ptable_ext->base, ext_base, 4);
    for(i = 0; i < 4; i++) {
      print_ptable_entry(pcnt, ptable + i);
      if(ptable[i].valid && !is_ext_ptable(ptable + i)) pcnt++;
    }
  }
}


char *get_screen(x86emu_mem_t *mem)
{
  unsigned u, x, y;
  unsigned base = 0xb8000;
  char *s, s_l[80 + 1];
  static char screen[80*25+1];

  *screen = 0;

  for(y = 0; y < 25; y++, base += 80 * 2) {
    for(x = 0; x < 80; x++) {
      u = vm_read_byte_noerr(mem, base + 2 * x);
      if(u < 0x20) u = ' ';
      if(u >= 0x7f) u = '?';
      s_l[x] = u;
    }
    s_l[x] = 0;
    for(s = s_l + x - 1; s >= s_l; s--) {
      if(*s != ' ') break;
      *s = 0;
    }

    if(*s_l) strcat(strcat(screen, s_l), "\n");
  }

  return screen;
}


void dump_screen(x86emu_mem_t *mem)
{
  printf("- - screen  - -\n%s- - - - - - - -\n", get_screen(mem));
}


