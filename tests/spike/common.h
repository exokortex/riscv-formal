
#define require_extension(_ext) do { } while (0)
#define require(_expression) do { if (!(_expression)) valid = false; } while (0)

typedef struct 
{
	uint64_t rdata, wdata, addr;
	int8_t optype; // width in bytes, negative for write
} mmu_t;

uint8_t load_uint8(mmu_t* self, uint64_t a) {
  assert(self->optype == 0);
  self->addr = a, self->optype = 1;
  return self->rdata;
}

uint16_t load_uint16(mmu_t* self, uint64_t a) {
  assert(self->optype == 0);
  self->addr = a, self->optype = 2;
  return self->rdata;
}

uint32_t load_uint32(mmu_t* self, uint64_t a) {
  assert(self->optype == 0);
  self->addr = a, self->optype = 4;
  return self->rdata;
}

uint64_t load_uint64(mmu_t* self, uint64_t a) {
  assert(self->optype == 0);
  self->addr = a, self->optype = 8;
  return self->rdata;
}

void store_uint8(mmu_t* self, uint64_t a, uint8_t d) {
  assert(self->optype == 0);
  self->addr = a, self->wdata = d, self->optype = -1;
}

void store_uint16(mmu_t* self, uint64_t a, uint16_t d) {
  assert(self->optype == 0);
  self->addr = a, self->wdata = d, self->optype = -2;
}

void store_uint32(mmu_t* self, uint64_t a, uint32_t d) {
  assert(self->optype == 0);
  self->addr = a, self->wdata = d, self->optype = -4;
}

void store_uint64(mmu_t* self, uint64_t a, uint64_t d) {
  assert(self->optype == 0);
  self->addr = a, self->wdata = d, self->optype = -8;
}

int8_t load_int8(mmu_t* self, uint64_t a) {
  return load_uint8(self, a);
}

int16_t load_int16(mmu_t* self, uint64_t a) {
  return load_uint16(self, a);
}

int32_t load_int32(mmu_t* self, uint64_t a) {
  return load_uint32(self, a);
}

int64_t load_int64(mmu_t* self, uint64_t a) {
  return load_uint64(self, a);
}

// ----- from riscv-isa-sim/riscv/decode.h with minor edits -----

typedef int64_t sreg_t;
typedef uint64_t reg_t;
typedef uint64_t freg_t;

#define NXPR (32)
#define NFPR (32)
#define NCSR (4096)

#define X_RA 1
#define X_SP 2

#define FP_RD_NE  0
#define FP_RD_0   1
#define FP_RD_DN  2
#define FP_RD_UP  3
#define FP_RD_NMM 4

#define FSR_RD_SHIFT 5
#define FSR_RD   (0x7 << FSR_RD_SHIFT)

#define FPEXC_NX 0x01
#define FPEXC_UF 0x02
#define FPEXC_OF 0x04
#define FPEXC_DZ 0x08
#define FPEXC_NV 0x10

#define FSR_AEXC_SHIFT 0
#define FSR_NVA  (FPEXC_NV << FSR_AEXC_SHIFT)
#define FSR_OFA  (FPEXC_OF << FSR_AEXC_SHIFT)
#define FSR_UFA  (FPEXC_UF << FSR_AEXC_SHIFT)
#define FSR_DZA  (FPEXC_DZ << FSR_AEXC_SHIFT)
#define FSR_NXA  (FPEXC_NX << FSR_AEXC_SHIFT)
#define FSR_AEXC (FSR_NVA | FSR_OFA | FSR_UFA | FSR_DZA | FSR_NXA)

#define insn_length(x) \
  (((x) & 0x03) < 0x03 ? 2 : \
   ((x) & 0x1f) < 0x1f ? 4 : \
   ((x) & 0x3f) < 0x3f ? 6 : \
   8)
#define MAX_INSN_LENGTH 8
#define PC_ALIGN 2

typedef uint64_t insn_bits_t;
typedef insn_bits_t insn_t;

//insn_bits_t b;
uint64_t x(insn_t self, int lo, int len) { return (self >> lo) & (((insn_bits_t)(1) << len)-1); }
uint64_t xs(insn_t self, int lo, int len) { return (int64_t)(self) << (64-lo-len) >> (64-len); }
uint64_t imm_sign(insn_t self) { return xs(self, 31, 1); }
insn_bits_t bits(insn_t self) { return self; }
int length(insn_t self) { return insn_length(self); }
int64_t i_imm(insn_t self) { return (int64_t)(self) >> 20; }
int64_t s_imm(insn_t self) { return x(self, 7, 5) + (xs(self, 25, 7) << 5); }
int64_t sb_imm(insn_t self) { return (x(self, 8, 4) << 1) + (x(self, 25,6) << 5) + (x(self, 7,1) << 11) + (imm_sign(self) << 12); }
int64_t u_imm(insn_t self) { return (int64_t)(self) >> 12 << 12; }
int64_t uj_imm(insn_t self) { return (x(self, 21, 10) << 1) + (x(self, 20, 1) << 11) + (x(self, 12, 8) << 12) + (imm_sign(self) << 20); }
uint64_t rd(insn_t self) { return x(self, 7, 5); }
uint64_t rs1(insn_t self) { return x(self, 15, 5); }
uint64_t rs2(insn_t self) { return x(self, 20, 5); }
uint64_t rs3(insn_t self) { return x(self, 27, 5); }
uint64_t rm(insn_t self) { return x(self, 12, 3); }
uint64_t csr(insn_t self) { return x(self, 20, 12); }

int64_t rvc_imm(insn_t self) { return x(self, 2, 5) + (xs(self, 12, 1) << 5); }
int64_t rvc_zimm(insn_t self) { return x(self, 2, 5) + (x(self, 12, 1) << 5); }
int64_t rvc_addi4spn_imm(insn_t self) { return (x(self, 6, 1) << 2) + (x(self, 5, 1) << 3) + (x(self, 11, 2) << 4) + (x(self, 7, 4) << 6); }
int64_t rvc_addi16sp_imm(insn_t self) { return (x(self, 6, 1) << 4) + (x(self, 2, 1) << 5) + (x(self, 5, 1) << 6) + (x(self, 3, 2) << 7) + (xs(self, 12, 1) << 9); }
int64_t rvc_lwsp_imm(insn_t self) { return (x(self, 4, 3) << 2) + (x(self, 12, 1) << 5) + (x(self, 2, 2) << 6); }
int64_t rvc_ldsp_imm(insn_t self) { return (x(self, 5, 2) << 3) + (x(self, 12, 1) << 5) + (x(self, 2, 3) << 6); }
int64_t rvc_swsp_imm(insn_t self) { return (x(self, 9, 4) << 2) + (x(self, 7, 2) << 6); }
int64_t rvc_sdsp_imm(insn_t self) { return (x(self, 10, 3) << 3) + (x(self, 7, 3) << 6); }
int64_t rvc_lw_imm(insn_t self) { return (x(self, 6, 1) << 2) + (x(self, 10, 3) << 3) + (x(self, 5, 1) << 6); }
int64_t rvc_ld_imm(insn_t self) { return (x(self, 10, 3) << 3) + (x(self, 5, 2) << 6); }
int64_t rvc_j_imm(insn_t self) { return (x(self, 3, 3) << 1) + (x(self, 11, 1) << 4) + (x(self, 2, 1) << 5) + (x(self, 7, 1) << 6) + (x(self, 6, 1) << 7) + (x(self, 9, 2) << 8) + (x(self, 8, 1) << 10) + (xs(self, 12, 1) << 11); }
int64_t rvc_b_imm(insn_t self) { return (x(self, 3, 2) << 1) + (x(self, 10, 2) << 3) + (x(self, 2, 1) << 5) + (x(self, 5, 2) << 6) + (xs(self, 12, 1) << 8); }
int64_t rvc_simm3(insn_t self) { return x(self, 10, 3); }
uint64_t rvc_rd(insn_t self) { return rd(self); }
uint64_t rvc_rs1(insn_t self) { return rd(self); }
uint64_t rvc_rs2(insn_t self) { return x(self, 2, 5); }
uint64_t rvc_rs1s(insn_t self) { return 8 + x(self, 7, 3); }
uint64_t rvc_rs2s(insn_t self) { return 8 + x(self, 2, 3); }

// helpful macros, etc
#define MMU (mmu)
#define STATE (post_state)
#define READ_REG(reg) STATE.XPR[reg]
#define READ_FREG(reg) STATE.FPR[reg]
#define RS1 READ_REG(rs1(insn))
#define RS2 READ_REG(rs2(insn))
#define WRITE_RD(value) WRITE_REG(rd(insn), value)

#define WRITE_REG(reg, value) do { reg_t v = value; STATE.XPR[reg] = reg ? v : 0; } while (0)
#define WRITE_FREG(reg, value) DO_WRITE_FREG(reg, value)

// RVC macros
#define WRITE_RVC_RS1S(value) WRITE_REG(rvc_rs1s(insn), value)
#define WRITE_RVC_RS2S(value) WRITE_REG(rvc_rs2s(insn), value)
#define WRITE_RVC_FRS2S(value) WRITE_FREG(rvc_rs2s(insn), value)
#define RVC_RS1 READ_REG(rvc_rs1(insn))
#define RVC_RS2 READ_REG(rvc_rs2(insn))
#define RVC_RS1S READ_REG(rvc_rs1s(insn))
#define RVC_RS2S READ_REG(rvc_rs2s(insn))
#define RVC_FRS2 READ_FREG(rvc_rs2(insn))
#define RVC_FRS2S READ_FREG(rvc_rs2s(insn))
#define RVC_SP READ_REG(X_SP)

// FPU macros
#define FRS1 READ_FREG(rs1(insn))
#define FRS2 READ_FREG(rs2(insn))
#define FRS3 READ_FREG(rs3(insn))
#define dirty_fp_state (STATE.mstatus |= MSTATUS_FS | (xlen == 64 ? MSTATUS64_SD : MSTATUS32_SD))
#define dirty_ext_state (STATE.mstatus |= MSTATUS_XS | (xlen == 64 ? MSTATUS64_SD : MSTATUS32_SD))
#define DO_WRITE_FREG(reg, value) (STATE.FPR.write(reg, value), dirty_fp_state)
#define WRITE_FRD(value) WRITE_FREG(rd(insn), value)

#define SHAMT (i_imm(insn) & 0x3F)
#define BRANCH_TARGET (pc + sb_imm(insn))
#define JUMP_TARGET (pc + uj_imm(insn))
#define RM ({ int rm = rm(insn); \
              if(rm == 7) rm = STATE.frm; \
              if(rm > 4) throw trap_illegal_instruction(); \
              rm; })

#define get_field(reg, mask) (((reg) & (decltype(reg))(mask)) / ((mask) & ~((mask) << 1)))
#define set_field(reg, mask, val) (((reg) & ~(decltype(reg))(mask)) | (((decltype(reg))(val) * ((mask) & ~((mask) << 1))) & (decltype(reg))(mask)))

#define sext32(x) ((sreg_t)(int32_t)(x))
#define zext32(x) ((reg_t)(uint32_t)(x))
#define sext_xlen(x) (((sreg_t)(x) << (64-xlen)) >> (64-xlen))
#define zext_xlen(x) (((reg_t)(x) << (64-xlen)) >> (64-xlen))

#define set_pc(x) do { STATE.pc = x; } while (0)


// ----- from riscv-isa-sim/riscv/processor.h translated from C++ to C with minor edits -----

typedef struct
{
  uint8_t prv;
  bool step;
  bool ebreakm;
  bool ebreakh;
  bool ebreaks;
  bool ebreaku;
  bool halt;
  uint8_t cause;
} dcsr_t;

// typedef enum
// {
//   ACTION_DEBUG_EXCEPTION = MCONTROL_ACTION_DEBUG_EXCEPTION,
//   ACTION_DEBUG_MODE = MCONTROL_ACTION_DEBUG_MODE,
//   ACTION_TRACE_START = MCONTROL_ACTION_TRACE_START,
//   ACTION_TRACE_STOP = MCONTROL_ACTION_TRACE_STOP,
//   ACTION_TRACE_EMIT = MCONTROL_ACTION_TRACE_EMIT
// } mcontrol_action_t;
//
// typedef enum
// {
//   MATCH_EQUAL = MCONTROL_MATCH_EQUAL,
//   MATCH_NAPOT = MCONTROL_MATCH_NAPOT,
//   MATCH_GE = MCONTROL_MATCH_GE,
//   MATCH_LT = MCONTROL_MATCH_LT,
//   MATCH_MASK_LOW = MCONTROL_MATCH_MASK_LOW,
//   MATCH_MASK_HIGH = MCONTROL_MATCH_MASK_HIGH
// } mcontrol_match_t;
//
// typedef struct
// {
//   uint8_t type;
//   bool dmode;
//   uint8_t maskmax;
//   bool select;
//   bool timing;
//   mcontrol_action_t action;
//   bool chain;
//   mcontrol_match_t match;
//   bool m;
//   bool h;
//   bool s;
//   bool u;
//   bool execute;
//   bool store;
//   bool load;
// } mcontrol_t;

// architectural state of a RISC-V hart
typedef struct
{
  reg_t pc;
  reg_t XPR[NXPR];
  freg_t FPR[NFPR];

  // control and status registers
  reg_t prv;    // TODO: Can this be an enum instead?
  reg_t mstatus;
  reg_t mepc;
  reg_t mbadaddr;
  reg_t mscratch;
  reg_t mtvec;
  reg_t mcause;
  reg_t minstret;
  reg_t mie;
  reg_t mip;
  reg_t medeleg;
  reg_t mideleg;
  uint32_t mucounteren;
  uint32_t mscounteren;
  reg_t sepc;
  reg_t sbadaddr;
  reg_t sscratch;
  reg_t stvec;
  reg_t sptbr;
  reg_t scause;
  reg_t dpc;
  reg_t dscratch;
  dcsr_t dcsr;
  reg_t tselect;
  // mcontrol_t mcontrol[num_triggers];
  // reg_t tdata2[num_triggers];

  uint32_t fflags;
  uint32_t frm;
  bool serialized; // whether timer CSRs are in a well-defined state

  // When true, execute a single instruction and then enter debug mode.  This
  // can only be set by executing dret.
  enum {
      STEP_NONE,
      STEP_STEPPING,
      STEP_STEPPED
  } single_step;

  reg_t load_reservation;
} state_t;
