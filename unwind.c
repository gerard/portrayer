#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <elf.h>
#include <dwarf.h>
#include "common.h"
#include "logging.h"

#if UINTPTR_MAX == 0xffffffff
#   define Elf_Ehdr     Elf32_Ehdr
#   define Elf_Phdr     Elf32_Phdr
#   define Elf_Off      Elf32_Off
#else
#   define Elf_Ehdr     Elf64_Ehdr
#   define Elf_Phdr     Elf64_Phdr
#   define Elf_Off      Elf64_Off
#endif

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

/* To understand this, the DWARFv3 spec is the canonical resource.
 * Nevertheless, if you don't want to become completely crazy, these are
 * helpful resources too:
 *   o http://www.airs.com/blog/archives/460     (the guy from the gold linker)
 *   o http://www.airs.com/blog/archives/462
 *   o $ dwarfdump -F -vv a.out                  (dwarf utilities)
 * The last command can be used to cross check the results that this code is
 * giving.
 */

/* WARNING:  This code is awfully hacky right now and it's not supposed to work
 *           in most of the cases.  For now should work only in really simple
 *           *static* x86_64 binaries compiled with -fomit-frame-pointer.  This
 *           is not the plan, but allows me to take shortcuts and I need to get
 *           something working before getting the motivation for writing really
 *           portable code.
 */


struct __attribute__((packed)) eh_frame_hdr {
    uint8_t version;
    uint8_t contents_pointer_encoding;
    uint8_t fde_count_encoding;
    uint8_t lookup_pointer_encoding;
    uint32_t contents_pointer;
    uint32_t fde_count;
    uint32_t lookup_pointer;
};

#define POP_BYTES(fd, off, bytes, buf) ({               \
    if (pread(fd, buf, bytes, off) < 0) {               \
        EXIT_WITH_FAILURE;                              \
    }                                                   \
    off += bytes;                                       \
})

#define POP_TYPE(fd, off, type) ({                      \
    type __ret;                                         \
    POP_BYTES(fd, off, sizeof(type), &__ret);           \
    __ret;                                              \
})



static int32_t cie_cfa_offset;
static int8_t code_alignment;
static int8_t data_alignment;

static uint64_t initial_fde_count;
static off_t initial_fde_offset;
static int initial_fd;

static void DUMP_BYTES(int fd, off_t offset, uint32_t len)
{
    if (len > 0x80) {
        len = 0x80;
        DEBUG("Cutting debug output: Too long dump [%d bytes]", len);
    }

    off_t initial_off = offset;
    __DEBUG("DUMP[%08llx]: ", offset);
    for (off_t i = initial_off; i < (initial_off + len); i++) {
        uint8_t byte = POP_TYPE(fd, offset, uint8_t);
        __DEBUG("0x%02x", byte);
        if ((i + 1) % 8 == 0) {
            __DEBUG("\nDUMP[%08llx]: ", i);
        } else {
            __DEBUG(" ");
        }
    }
    DEBUG("");
}

void decode_cfa_opcodes(int fd, off_t offset, uint32_t cfa_len, int32_t *stack_offset,
                        void *start_rip, const void const *process_rip)
{
    off_t cfa_end = offset + cfa_len;
    off_t initial_offset = offset;
    *stack_offset = cie_cfa_offset;

    if (unlikely(start_rip > process_rip)) {
        EXIT_WITH_FAILURE_STR("Incorrect rip while decoding CFA");
    }

    /* Again, this is full of LEB128 encoded types, and we are assuming
     * that these values are < 128 so they are equivalent to uint8_t */
    /* TODO: Lots of CFA opcodes missing... */
    DEBUG("DW_CFA decode start [len = %d]", cfa_len);
    while (offset < cfa_end) {
        DEBUG("OFF: %p, END: %p", (void *)offset, cfa_end);
        uint8_t opcode = POP_TYPE(fd, offset, uint8_t);
        switch (opcode) {
        case DW_CFA_def_cfa:
            offset += 1;    /* Here is the stack pointer register */
            *stack_offset = POP_TYPE(fd, offset, uint8_t) * code_alignment;
            DEBUG("   DW_CFA_def_cfa");
            break;
        case DW_CFA_def_cfa_offset:
            *stack_offset = POP_TYPE(fd, offset, uint8_t);
            DEBUG("   DW_CFA_def_cfa_offset");
            break;
        case DW_CFA_def_cfa_sf:
            offset += 1;
            *stack_offset = POP_TYPE(fd, offset, uint8_t) * code_alignment;
            DEBUG("   DW_CFA_def_cfa_sf");
            break;
        case DW_CFA_offset ... (DW_CFA_offset + DW_CFA_high_user):
            offset += 1;
            DEBUG("   DW_CFA_offset");
            break;
        case DW_CFA_advance_loc ... (DW_CFA_advance_loc + DW_CFA_high_user):
            process_rip += (opcode - DW_CFA_advance_loc);
            DEBUG("   DW_CFA_advance_loc");
            break;
        case DW_CFA_nop:
            DEBUG("   DW_CFA_nop");
            break;
        default:
            DEBUG("Unrecognized CFA opcode: 0x%02x@0x%p", opcode, (void *)offset);
            DUMP_BYTES(fd, initial_offset, cfa_len);
            EXIT_WITH_FAILURE_STR("Don't know how to continue");
        }

        if (start_rip && start_rip > process_rip) {
            DEBUG("CFA early exit");
            /* No need to decode more, current rip should have already the
             * right stack offset value */
            break;
        }
    }
    DEBUG("DW_CFA decode end");
}

uint32_t augmentation_decode(int fd, uint32_t offset)
{
    uint32_t initial_offset = offset;

    if (POP_TYPE(fd, offset, char) != 'z') {
        EXIT_WITH_FAILURE_STR("Unexpected augmentation");
    }

    while (POP_TYPE(fd, offset, char) != '\0');
    return offset - initial_offset;
}

void decode_cie(int fd, uint32_t offset, uint32_t cie_len)
{
    uint32_t cie_start = offset;

    if (POP_TYPE(fd, offset, uint32_t) != 0) {
        EXIT_WITH_FAILURE_STR("Unexpected ID for CIE block");
    }

    if (POP_TYPE(fd, offset, uint8_t) != 1) {
        EXIT_WITH_FAILURE_STR("Unexpected CIE version");
    }

    offset += augmentation_decode(fd, offset);

    /* These are actually LEB128.  We just don't expect it to be
     * more than 128 for now, so it's equivalent to an uint8_t */
    code_alignment = POP_TYPE(fd, offset, uint8_t);
    data_alignment = -8;    /* We set this assuming the real encoded value is... */
    if (POP_TYPE(fd, offset, uint8_t) != 0x78) {
        EXIT_WITH_FAILURE_STR("Unexpected data_alignment");
    }

    /* uint8_t ra_reg = */POP_TYPE(fd, offset, uint8_t);
    uint8_t augment_len = POP_TYPE(fd, offset, uint8_t);
    offset += augment_len;

    off_t cfa_opcodes_len = cie_len - (offset - cie_start);
    //DEBUG("Decoding CIE CFA at %p + 0x%04x", (void *)(uint64_t)offset, cfa_opcodes_len);
    decode_cfa_opcodes(fd, offset, cfa_opcodes_len, &cie_cfa_offset, NULL, NULL);
    //DEBUG("CIE CFA initial offset: %d bytes", cie_cfa_offset);
    offset += cfa_opcodes_len;  /* Unnecessary... */

    initial_fde_offset = offset;
    initial_fd = fd;
}

int decode_fde(int fd, uint32_t offset, const void const *process_rip,
               uint32_t fde_len, int32_t *stack_offset)
{
    /* Assuming pcrel | sdata4 FDE encoding */
    uint32_t fde_id     = POP_TYPE(fd, offset, uint32_t);

    if (fde_id == 0) {
        /* This is a CIE.  Parse it and skip to the next FDE. */
        offset -= sizeof(uint32_t);
        decode_cie(fd, offset, fde_len);
        return 0;
    }

    void *start_off     = (void *)(uint64_t)offset;
    int32_t fde_start   = POP_TYPE(fd, offset, int32_t);
    uint32_t fde_off    = POP_TYPE(fd, offset, uint32_t);
    void *fde_rip_start = start_off + fde_start;

    if (process_rip >= fde_rip_start && process_rip < (fde_rip_start + fde_off)) {
        DEBUG("0x%08x +0x%04x [ID: %x LEN:%x] Looking for %p", (uint32_t)(uint64_t)fde_rip_start, fde_off, 
                                                                 fde_id, fde_len, process_rip);
        DEBUG("%p %p %p", fde_rip_start, process_rip, fde_rip_start + fde_off);
        /* Found the fde belonging to this frame */
        DEBUG("Found FDE: 0x%08x +0x%04x", fde_rip_start, fde_off);
        uint8_t augdata_len = POP_TYPE(fd, offset, uint8_t);
        if (augdata_len != 0) {
            EXIT_WITH_FAILURE_STR("Unsupported augmentation data found in FDE");
        }

        //uint32_t cfa_len = (offset - (uint32_t)(start_off + 2));
        uint32_t cfa_len = fde_len - 13;
        *stack_offset = cie_cfa_offset;      /* Initialize to CIE CFA opcode values */
        decode_cfa_opcodes(fd, offset, cfa_len, stack_offset, fde_rip_start, process_rip);
        return 1;
    } else {
        return 0;
    }
}

int32_t unwind_find_caller_offset(pid_t pid, void *rip)
{
    off_t offset = initial_fde_offset;
    int fd = initial_fd;

    DEBUG("Analyzing total of %d FDEs", (int)initial_fde_count);
    for (int j = 0; j < initial_fde_count; j++) {
        uint32_t fde_len = POP_TYPE(fd, offset, uint32_t);
        int32_t stack_offset;

        if (decode_fde(fd, offset, rip, fde_len, &stack_offset)) {
            DEBUG("Success");
            return stack_offset;
        }
        offset += fde_len;
    }

    DEBUG("Couldn't find right FDE for IP: %p", (void *)rip);
    EXIT_WITH_FAILURE_STR("Don't know how to continue");
    return 0;
}

int unwind_prepare(char *file)
{
    Elf_Ehdr ehdr;
    Elf_Phdr phdr;
    int fd;

    if ((fd = open(file, O_RDONLY)) < 0) {
        EXIT_WITH_FAILURE;
    }

    if (pread(fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr)) {
        EXIT_WITH_FAILURE;
    }

    Elf_Off phdrs_offset = ehdr.e_phoff;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (pread(fd, &phdr, ehdr.e_phentsize, phdrs_offset) != sizeof(phdr)) {
            EXIT_WITH_FAILURE;
        }

        struct eh_frame_hdr eh_frame_hdr_data;
        switch (phdr.p_type) {
        case PT_GNU_EH_FRAME:
            if (pread(fd, &eh_frame_hdr_data, sizeof(struct eh_frame_hdr), phdr.p_offset) < 0) {
                EXIT_WITH_FAILURE;
            }

            /* These values are hardcoded here, but dwarf.h should actually be used */
            if (eh_frame_hdr_data.version != 1 ||
                eh_frame_hdr_data.contents_pointer_encoding != 0x1b ||
                eh_frame_hdr_data.fde_count_encoding != 0x03 ||
                eh_frame_hdr_data.lookup_pointer_encoding != 0x3b) {
                EXIT_WITH_FAILURE_STR("Unknown .eh_frame_hdr format");
            }
            DEBUG("Valid .eh_frame_hdr section found in address: %p", (void *)phdr.p_offset);
            DEBUG(".eh_frame contains %d entries", eh_frame_hdr_data.fde_count);

            off_t absolute_contents_off = phdr.p_offset + offsetof(struct eh_frame_hdr, contents_pointer)
                                                        + eh_frame_hdr_data.contents_pointer;
            //off_t cie_off = absolute_contents_off;

            DEBUG(".eh_frame should be at %p", (void *)absolute_contents_off);
            uint32_t cie_len = POP_TYPE(fd, absolute_contents_off, uint32_t);
            if (cie_len == 0xFFFFFFFF) {
                EXIT_WITH_FAILURE_STR("Unsupported format (.debug_frame)");
            }

            initial_fde_count = eh_frame_hdr_data.fde_count;
            decode_cie(fd, absolute_contents_off, cie_len);
            break;
        default:
            break;
        }

        phdrs_offset += ehdr.e_phentsize;
    }

    if (initial_fd == 0) {
        EXIT_WITH_FAILURE_STR("Failed to find PT_GNU_EH_FRAME block");
    }
    return 0;
}
