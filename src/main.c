/*

   A. Run code from inside the target process.
   B. Manually load shared object and all its dependency, and give it a thread to run.

   C. Combine A & B -> Write manual mapper to target process and load our shared object into 
        target process.

*/
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <elf.h>
#include <malloc.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "TargetBrief/TargetBrief_t.h"
#include "ShellCode/ShellCode.h"
#include "Util/Assertions/Assertions.h"


#define nullptr    ((void*)NULL)
#define TARGET_DLL "TestELF/testlib.so"


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static int  DocumentELF(const char* szFileName);
static int  GetElfClass(FILE* pFile);
static void PrintElf64_Ehdr(Elf64_Ehdr* pHeader);
static void PrintElfHeader32(Elf32_Ehdr* pHeader);


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int main(int nArgs, char** szArgs)
{
    if(nArgs <= 1)
    {
        printf("Target name not specified\n");
        return 1;
    }


    // Construct target brief.
    TargetBrief_t target; const char* szTargetName = szArgs[1];
    if(TargetBrief_InitializeName(&target, szTargetName) == false)
    {
        printf("Failed to gather information about target : %s\n", szTargetName);
        return 1;
    }
    printf("(getpid : %d), Name : %s, PID : %d\n", getpid(), target.m_szTargetName, target.m_iTargetPID);
    printf("\n");


    ShellCode_MapSharedObject(TARGET_DLL, &target);


    return 0;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static int DocumentELF(const char* szFileName)
{
    FILE* pFile = fopen(szFileName, "rb");
    if(pFile == nullptr)
    {
        printf("Failed to open .so file : %s\n", szFileName);
        return 0;
    }


    // determine if this elf file is 32 bit or 64 bit.
    int iElfClass = GetElfClass(pFile);
    if(iElfClass != ELFCLASS64)
    {
        printf("Elf file has an invalid class : %d\n", iElfClass);
        fclose(pFile);
        return 0;
    }


    // goto starting of file.
    if(fseek(pFile, 0, SEEK_SET) != 0)
    {
        printf("Unexpected error encountered @ fseek\n");
        fclose(pFile);
        return 0;
    }

    Elf64_Ehdr iElfHeader;
    int         nItemsRead = fread(&iElfHeader, 1, sizeof(Elf64_Ehdr), pFile);
    if(nItemsRead <= 0)
    {
        printf("Failed to read ELF header\n");
        fclose(pFile);
        return 0;
    }


    printf("ELF Header Bytes : \n");
    for(int i = 0; i < sizeof(Elf64_Ehdr); i++)
    {
        printf("%02x ", (int)(((char*)&iElfHeader)[i]));
        if(((i + 1) % 16) == 0)
            printf("\n");
    }
    printf("\n");


    PrintElf64_Ehdr(&iElfHeader);


    // Program headers...
    fseek(pFile, iElfHeader.e_phoff, SEEK_SET);
    assertion(iElfHeader.e_phentsize == sizeof(Elf64_Phdr) && "Program heaader size doesn't match program header struct size");
    size_t      nPHBytes       = sizeof(Elf64_Phdr) * iElfHeader.e_phnum;
    Elf64_Phdr* pProgramHeader = (Elf64_Phdr*)malloc(nPHBytes);
    fread(pProgramHeader, 1, nPHBytes, pFile);

    for(int i = 0; i < iElfHeader.e_phnum; i++)
    {
        switch(pProgramHeader[i].p_type)
        {
            case PT_LOAD:         printf("PT_LOAD");         break;
            case PT_DYNAMIC:      printf("PT_DYNAMIC");      break;
            case PT_INTERP:       printf("PT_INTERP");       break;
            case PT_NOTE:         printf("PT_NOTE");         break;
            case PT_SHLIB:        printf("PT_SHLIB");        break;
            case PT_PHDR:         printf("PT_PHDR");         break;
            case PT_TLS:          printf("PT_TLS");          break;
            case PT_NUM:          printf("PT_NUM");          break;
            case PT_LOOS:         printf("PT_LOOS");         break;
            case PT_GNU_EH_FRAME: printf("PT_GNU_EH_FRAME"); break;
            case PT_GNU_STACK:    printf("PT_GNU_STACK");    break;
            case PT_GNU_RELRO:    printf("PT_GNU_RELRO");    break;
            case PT_GNU_PROPERTY: printf("PT_GNU_PROPERTY"); break;
            case PT_GNU_SFRAME:   printf("PT_GNU_SFRAME");   break;
            default:              printf("Invalid section type"); break;
        }
        printf("\n");
    }

    free(pProgramHeader);
    fclose(pFile);
    return 1;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static int GetElfClass(FILE* pFile)
{
    long iCursorPos = ftell(pFile);

    char buffer[EI_NIDENT] = {0};
    fread(buffer, 1, EI_NIDENT, pFile);

    // restore cursor pos.
    fseek(pFile, iCursorPos, SEEK_SET);
    return buffer[EI_CLASS];
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void PrintElf64_Ehdr(Elf64_Ehdr* pHeader)
{
    printf("Magic                        : '%c%c%c%c'\n", pHeader->e_ident[0], pHeader->e_ident[1], pHeader->e_ident[2], pHeader->e_ident[3]);
    printf("ELF class                    : ");
    switch(pHeader->e_ident[EI_CLASS])
    {
        case ELFCLASSNONE: printf("Invalid class"); break;
        case ELFCLASS32:   printf("32-bit object"); break;
        case ELFCLASS64:   printf("64-bit object"); break;
        default: printf("Undefined class"); break;
    }
    printf("\n");

    printf("Data Encoding                : ");
    switch(pHeader->e_ident[EI_DATA])
    {
        case ELFDATA2LSB: printf("Little endian"); break;
        case ELFDATA2MSB: printf("Big endian");    break;
        default: printf("Invalid data encoding");  break;
    }
    printf("\n");


    printf("File Version                 : %d\n", (int)pHeader->e_ident[EI_VERSION]);


    printf("Application Binary Interface : ");
    switch(pHeader->e_ident[EI_OSABI])
    {
        case ELFOSABI_SYSV:       printf("UNIX System V ABI");                 break;
        case ELFOSABI_HPUX:       printf("HP-UX");                             break;
        case ELFOSABI_NETBSD:     printf("NetBSD");                            break;
        case ELFOSABI_GNU:        printf("Object uses GNU ELF extensions");    break;
        case ELFOSABI_SOLARIS:    printf("Sun Solaris");                       break;
        case ELFOSABI_AIX:        printf("IBM AIX");                           break;
        case ELFOSABI_IRIX:       printf("SGI Irix");                          break;
        case ELFOSABI_FREEBSD:    printf("FreeBSD");                           break;
        case ELFOSABI_TRU64:      printf("Compaq TRU64 UNIX");                 break;
        case ELFOSABI_MODESTO:    printf("Novell Modesto");                    break;
        case ELFOSABI_OPENBSD:    printf("OpenBSD");                           break;
        case ELFOSABI_ARM_AEABI:  printf("ARM EABI");                          break;
        case ELFOSABI_ARM:        printf("ARM");                               break;
        case ELFOSABI_STANDALONE: printf("Standalone (embedded) application"); break;
        default:                  printf("Invalid ABI");                       break;

    }
    printf("\n");


    printf("File Type                    : ");
    switch(pHeader->e_type)
    {
        case ET_REL:  printf("Relocatable file");   break;
        case ET_EXEC: printf("Executable file");    break;
        case ET_DYN:  printf("Shared object file"); break;
        case ET_CORE: printf("Core file");          break;
        default:      printf("Invalid file type");  break;
    }
    printf("\n");


    printf("Machine                      : ");
    switch(pHeader->e_machine)
    {
        case EM_M32:           printf("AT&T WE 32100");                                       break;
        case EM_SPARC:         printf("SUN SPARC");                                           break;
        case EM_386:           printf("Intel 80386");                                         break;
        case EM_68K:           printf("Motorola m68k family");                                break;
        case EM_88K:           printf("Motorola m88k family");                                break;
        case EM_IAMCU:         printf("Intel MCU");                                           break;
        case EM_860:           printf("Intel 80860");                                         break;
        case EM_MIPS:          printf("MIPS R3000 big-endian");                               break;
        case EM_S370:          printf("IBM System/370");                                      break;
        case EM_MIPS_RS3_LE:   printf("MIPS R3000 little-endian");                            break;
        case EM_PARISC:        printf("HPPA");                                                break;
        case EM_VPP500:        printf("Fujitsu VPP500");                                      break;
        case EM_SPARC32PLUS:   printf("Sun's v8plus");                                        break;
        case EM_960:           printf("Intel 80960");                                         break;
        case EM_PPC:           printf("PowerPC");                                             break;
        case EM_PPC64:         printf("PowerPC 64-bit");                                      break;
        case EM_S390:          printf("IBM S390");                                            break;
        case EM_SPU:           printf("IBM SPU/SPC");                                         break;
        case EM_V800:          printf("NEC V800 series");                                     break;
        case EM_FR20:          printf("Fujitsu FR20");                                        break;
        case EM_RH32:          printf("TRW RH-32");                                           break;
        case EM_RCE:           printf("Motorola RCE");                                        break;
        case EM_ARM:           printf("ARM");                                                 break;
        case EM_FAKE_ALPHA:    printf("Digital Alpha");                                       break;
        case EM_SH:            printf("Hitachi SH");                                          break;
        case EM_SPARCV9:       printf("SPARC v9 64-bit");                                     break;
        case EM_TRICORE:       printf("Siemens Tricore");                                     break;
        case EM_ARC:           printf("Argonaut RISC Core");                                  break;
        case EM_H8_300:        printf("Hitachi H8/300");                                      break;
        case EM_H8_300H:       printf("Hitachi H8/300H");                                     break;
        case EM_H8S:           printf("Hitachi H8S");                                         break;
        case EM_H8_500:        printf("Hitachi H8/500");                                      break;
        case EM_IA_64:         printf("Intel Merced");                                        break;
        case EM_MIPS_X:        printf("Stanford MIPS-X");                                     break;
        case EM_COLDFIRE:      printf("Motorola Coldfire");                                   break;
        case EM_68HC12:        printf("Motorola M68HC12");                                    break;
        case EM_MMA:           printf("Fujitsu MMA Multimedia Accelerator");                  break;
        case EM_PCP:           printf("Siemens PCP");                                         break;
        case EM_NCPU:          printf("Sony nCPU embedded RISC");                             break;
        case EM_NDR1:          printf("Denso NDR1 microprocessor");                           break;
        case EM_STARCORE:      printf("Motorola Start*Core processor");                       break;
        case EM_ME16:          printf("Toyota ME16 processor");                               break;
        case EM_ST100:         printf("STMicroelectronic ST100 processor");                   break;
        case EM_TINYJ:         printf("Advanced Logic Corp. Tinyj emb.fam");                  break;
        case EM_X86_64:        printf("AMD x86-64 architecture");                             break;
        case EM_PDSP:          printf("Sony DSP Processor");                                  break;
        case EM_PDP10:         printf("Digital PDP-10");                                      break;
        case EM_PDP11:         printf("Digital PDP-11");                                      break;
        case EM_FX66:          printf("Siemens FX66 microcontroller");                        break;
        case EM_ST9PLUS:       printf("STMicroelectronics ST9+ 8/16 mc");                     break;
        case EM_ST7:           printf("STmicroelectronics ST7 8 bit mc");                     break;
        case EM_68HC16:        printf("Motorola MC68HC16 microcontroller");                   break;
        case EM_68HC11:        printf("Motorola MC68HC11 microcontroller");                   break;
        case EM_68HC08:        printf("Motorola MC68HC08 microcontroller");                   break;
        case EM_68HC05:        printf("Motorola MC68HC05 microcontroller");                   break;
        case EM_SVX:           printf("Silicon Graphics SVx");                                break;
        case EM_ST19:          printf("STMicroelectronics ST19 8 bit mc");                    break;
        case EM_VAX:           printf("Digital VAX");                                         break;
        case EM_CRIS:          printf("Axis Communications 32-bit emb.proc");                 break;
        case EM_JAVELIN:       printf("Infineon Technologies 32-bit emb.proc");               break;
        case EM_FIREPATH:      printf("Element 14 64-bit DSP Processor");                     break;
        case EM_ZSP:           printf("LSI Logic 16-bit DSP Processor");                      break;
        case EM_MMIX:          printf("Donald Knuth's educational 64-bit proc");              break;
        case EM_HUANY:         printf("Harvard University machine-independent object files"); break;
        case EM_PRISM:         printf("SiTera Prism");                                        break;
        case EM_AVR:           printf("Atmel AVR 8-bit microcontroller");                     break;
        case EM_FR30:          printf("Fujitsu FR30");                                        break;
        case EM_D10V:          printf("Mitsubishi D10V");                                     break;
        case EM_D30V:          printf("Mitsubishi D30V");                                     break;
        case EM_V850:          printf("NEC v850");                                            break;
        case EM_M32R:          printf("Mitsubishi M32R");                                     break;
        case EM_MN10300:       printf("Matsushita MN10300");                                  break;
        case EM_MN10200:       printf("Matsushita MN10200");                                  break;
        case EM_PJ:            printf("picoJava");                                            break;
        case EM_OPENRISC:      printf("OpenRISC 32-bit embedded processor");                  break;
        case EM_ARC_COMPACT:   printf("ARC International ARCompact");                         break;
        case EM_XTENSA:        printf("Tensilica Xtensa Architecture");                       break;
        case EM_VIDEOCORE:     printf("Alphamosaic VideoCore");                               break;
        case EM_TMM_GPP:       printf("Thompson Multimedia General Purpose Proc");            break;
        case EM_NS32K:         printf("National Semi. 32000");                                break;
        case EM_TPC:           printf("Tenor Network TPC");                                   break;
        case EM_SNP1K:         printf("Trebia SNP 1000");                                     break;
        case EM_ST200:         printf("STMicroelectronics ST200");                            break;
        case EM_IP2K:          printf("* Ubicom IP2xxx");                                     break;
        case EM_MAX:           printf("* MAX processor");                                     break;
        case EM_CR:            printf("* National Semi. CompactRISC");                        break;
        case EM_F2MC16:        printf("Fujitsu F2MC16");                                      break;
        case EM_MSP430:        printf("Texas Instruments msp430");                            break;
        case EM_BLACKFIN:      printf("Analog Devices Blackfin DSP");                         break;
        case EM_SE_C33:        printf("Seiko Epson S1C33 family");                            break;
        case EM_SEP:           printf("* Sharp embedded microprocessor");                     break;
        case EM_ARCA:          printf("* Arca RISC");                                         break;
        case EM_UNICORE:       printf("PKU-Unity & MPRC Peking Uni. mc series");              break;
        case EM_EXCESS:        printf("eXcess configurable cpu");                             break;
        case EM_DXP:           printf("* Icera Semi. Deep Execution Processor");              break;
        case EM_ALTERA_NIOS2:  printf("Altera Nios II");                                      break;
        case EM_CRX:           printf("* National Semi. CompactRISC CRX");                    break;
        case EM_XGATE:         printf("Motorola XGATE");                                      break;
        case EM_C166:          printf("* Infineon C16x/XC16x");                               break;
        case EM_M16C:          printf("* Renesas M16C");                                      break;
        case EM_DSPIC30F:      printf("Microchip Technology dsPIC30F");                       break;
        case EM_CE:            printf("* Freescale Communication Engine RISC");               break;
        case EM_M32C:          printf("* Renesas M32C");                                      break;
        case EM_TSK3000:       printf("Altium TSK3000");                                      break;
        case EM_RS08:          printf("* Freescale RS08");                                    break;
        case EM_SHARC:         printf("Analog Devices SHARC family");                         break;
        case EM_ECOG2:         printf("Cyan Technology eCOG2");                               break;
        case EM_SCORE7:        printf("Sunplus S+core7 RISC");                                break;
        case EM_DSP24:         printf("New Japan Radio (NJR) 24-bit DSP");                    break;
        case EM_VIDEOCORE3:    printf("Broadcom VideoCore III");                              break;
        case EM_LATTICEMICO32: printf("RISC for Lattice FPGA");                               break;
        case EM_SE_C17:        printf("Seiko Epson C17");                                     break;
        case EM_TI_C6000:      printf("Texas Instruments TMS320C6000 DSP");                   break;
        case EM_TI_C2000:      printf("Texas Instruments TMS320C2000 DSP");                   break;
        case EM_TI_C5500:      printf("Texas Instruments TMS320C55x DSP");                    break;
        case EM_TI_ARP32:      printf("Texas Instruments App. Specific RISC");                break;
        case EM_TI_PRU:        printf("Texas Instruments Prog. Realtime Unit");               break;
        case EM_MMDSP_PLUS:    printf("STMicroelectronics 64bit VLIW DSP");                   break;
        case EM_CYPRESS_M8C:   printf("Cypress M8C");                                         break;
        case EM_R32C:          printf("* Renesas R32C");                                      break;
        case EM_TRIMEDIA:      printf("NXP Semi. TriMedia");                                  break;
        case EM_QDSP6:         printf("QUALCOMM DSP6");                                       break;
        case EM_8051:          printf("* Intel 8051 and variants");                           break;
        case EM_STXP7X:        printf("STMicroelectronics STxP7x");                           break;
        case EM_NDS32:         printf("Andes Tech. compact code emb. RISC");                  break;
        case EM_ECOG1X:        printf("Cyan Technology eCOG1X");                              break;
        case EM_MAXQ30:        printf("Dallas Semi. MAXQ30 mc");                              break;
        case EM_XIMO16:        printf("New Japan Radio (NJR) 16-bit DSP");                    break;
        case EM_MANIK:         printf("M2000 Reconfigurable RISC");                           break;
        case EM_CRAYNV2:       printf("Cray NV2 vector architecture");                        break;
        case EM_RX:            printf("* Renesas RX");                                        break;
        case EM_METAG:         printf("Imagination Tech. META");                              break;
        case EM_MCST_ELBRUS:   printf("MCST Elbrus");                                         break;
        case EM_ECOG16:        printf("Cyan Technology eCOG16");                              break;
        case EM_CR16:          printf("* National Semi. CompactRISC CR16");                   break;
        case EM_ETPU:          printf("* Freescale Extended Time Processing Unit");           break;
        case EM_SLE9X:         printf("Infineon Tech. SLE9X");                                break;
        case EM_L10M:          printf("* Intel L10M");                                        break;
        case EM_K10M:          printf("* Intel K10M");                                        break;
        case EM_AARCH64:       printf("ARM AARCH64");                                         break;
        case EM_AVR32:         printf("Amtel 32-bit microprocessor");                         break;
        case EM_STM8:          printf("* STMicroelectronics STM8");                           break;
        case EM_TILE64:        printf("Tilera TILE64");                                       break;
        case EM_TILEPRO:       printf("Tilera TILEPro");                                      break;
        case EM_MICROBLAZE:    printf("Xilinx MicroBlaze");                                   break;
        case EM_CUDA:          printf("* NVIDIA CUDA");                                       break;
        case EM_TILEGX:        printf("Tilera TILE-Gx");                                      break;
        case EM_CLOUDSHIELD:   printf("CloudShield");                                         break;
        case EM_COREA_1ST:     printf("KIPO-KAIST Core-A 1st gen.");                          break;
        case EM_COREA_2ND:     printf("KIPO-KAIST Core-A 2nd gen.");                          break;
        case EM_ARCV2:         printf("Synopsys ARCv2 ISA");                                  break;
        case EM_OPEN8:         printf("Open8 RISC");                                          break;
        case EM_RL78:          printf("* Renesas RL78");                                      break;
        case EM_VIDEOCORE5:    printf("Broadcom VideoCore V");                                break;
        case EM_78KOR:         printf("Renesas 78KOR");                                       break;
        case EM_56800EX:       printf("Freescale 56800EX DSC");                               break;
        case EM_BA1:           printf("* Beyond BA1");                                        break;
        case EM_BA2:           printf("* Beyond BA2");                                        break;
        case EM_XCORE:         printf("XMOS xCORE");                                          break;
        case EM_MCHP_PIC:      printf("Microchip 8-bit PIC(r)");                              break;
        case EM_INTELGT:       printf("Intel Graphics Technology");                           break;
        case EM_KM32:          printf("  KM211 KM32");                                        break;
        case EM_KMX32:         printf("KM211 KMX32");                                         break;
        case EM_EMX16:         printf("KM211 KMX16");                                         break;
        case EM_EMX8:          printf("  KM211 KMX8");                                        break;
        case EM_KVARC:         printf("KM211 KVARC");                                         break;
        case EM_CDP:           printf("  Paneve CDP");                                        break;
        case EM_COGE:          printf("  Cognitive Smart Memory Processor");                  break;
        case EM_COOL:          printf("  Bluechip CoolEngine");                               break;
        case EM_NORC:          printf("  Nanoradio Optimized RISC");                          break;
        case EM_CSR_KALIMBA:   printf("CSR Kalimba");                                         break;
        case EM_Z80:           printf("  Zilog Z80");                                         break;
        case EM_VISIUM:        printf("Controls and Data Services VISIUMcore");               break;
        case EM_FT32:          printf("  FTDI Chip FT32");                                    break;
        case EM_MOXIE:         printf("Moxie processor");                                     break;
        case EM_AMDGPU:        printf("AMD GPU");                                             break;
        case EM_RISCV:         printf("RISC-V");                                              break;
        case EM_BPF:           printf("Linux BPF -- in-kernel virtual machine");              break;
        case EM_CSKY:          printf("C-SKY");                                               break;
        case EM_LOONGARCH:     printf("LoongArch");                                           break;

        default: printf("Invalid machine code"); break;
    }
    printf("\n");


    printf("Entry                        : %p\n", (void*)pHeader->e_entry);
    printf("Program Header Table Offset  : %lu\n", pHeader->e_phoff);
    printf("Section Header Table Offset  : %lu\n", pHeader->e_shoff);
    printf("Flags                        : %u\n",  pHeader->e_flags);
    printf("ELF Header Size              : %u\n",  pHeader->e_ehsize);
    printf("Program Header Count         : %u\n",  pHeader->e_phnum);
    printf("Program Header Size          : %u\n",  pHeader->e_phentsize);
    printf("Section Header Count         : %u\n",  pHeader->e_shnum);
    printf("Section Header Size          : %u\n",  pHeader->e_shentsize);
}
