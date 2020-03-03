# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2004,2005,2006 4tphi Research
#
# Authors:
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

import struct
import volatility.plugins.addrspaces.paged as paged
import volatility.obj as obj

entry_size = 8
pointer_size = 4
page_shift = 12
ptrs_per_pte = 1024
ptrs_per_pgd = 1024
ptrs_per_pae_pte = 512
ptrs_per_pae_pgd = 512
ptrs_per_pdpi = 4
pgdir_shift = 22
pdpi_shift = 30
pdptb_shift = 5
pde_shift = 21
ptrs_per_pde = 512
ptrs_page = 2048

class I386PagedMemory(paged.AbstractWritablePagedMemory):
    """ Standard IA-32 paging address space.

    This class implements the IA-32 paging address space. It is responsible
    for translating each virtual (linear) address to a physical address.
    This is accomplished using hierachical paging structures.
    Every paging structure is 4096 bytes and is composed of entries.
    Each entry is 32 bits.  The first paging structure is located at the
    physical address found in CR3 (dtb).

    Additional Resources:
     - Intel(R) 64 and IA-32 Architectures Software Developer's Manual
       Volume 3A: System Programming Guide. Section 4.3
       http://www.intel.com/products/processor/manuals/index.htm
     - AMD64 Architecture Programmer's Manual Volume 2: System Programming
       http://support.amd.com/us/Processor_TechDocs/24593_APM_v2.pdf
     - N. Petroni, A. Walters, T. Fraser, and W. Arbaugh, "FATKit: A Framework
       for the Extraction and Analysis of Digital Forensic Data from Volatile
       System Memory" ,Digital Investigation Journal 3(4):197-210, December 2006.
       (submitted February 2006)
     - N. P. Maclean, "Acquisition and Analysis of Windows Memory,"
       University of Strathclyde, Glasgow, April 2006.
     - Russinovich, M., & Solomon, D., & Ionescu, A.
       "Windows Internals, 5th Edition", Microsoft Press, 2009.
    """
    order = 70
    pae = False
    paging_address_space = True
    checkname = 'IA32ValidAS'
    # Hardcoded page info to avoid expensive recalculation
    minimum_size = 0x1000
    alignment_gcd = 0x1000
    _long_struct = struct.Struct('<I')

    def __init__(self, image_path, dtb = 0):
        self.image_path = image_path
        self.dtb = dtb

    def is_valid_profile(self, profile):
        return profile.metadata.get('memory_model', '32bit') == '32bit' or profile.metadata.get('os', 'Unknown').lower() == 'mac'

    def entry_present(self, entry):
        if entry:
            if (entry & 1):
                return True

            #arch = self.profile.metadata.get('os', 'Unknown').lower()
            arch = "linux"

            # The page is in transition and not a prototype.
            # Thus, we will treat it as present.
            if arch == "windows" and ((entry & (1 << 11)) and not (entry & (1 << 10))):
                return True

            # Linux pages that have had mprotect(...PROT_NONE) called on them
            # have the present bit cleared and global bit set
            if arch == "linux" and (entry & (1 << 8)):
                return True

        return False

    def page_size_flag(self, entry):
        if (entry & (1 << 7)) == (1 << 7):
            return True
        return False

    def is_user_page(self, entry):
        return entry & (1 << 2) == (1 << 2)

    def is_supervisor_page(self, entry):
        return not self.is_user_page(entry)

    def is_writeable(self, entry):
        return entry & (1 << 1) == (1 << 1)
        
    def is_dirty(self, entry):
        return entry & (1 << 6) == (1 << 6)
        
    def is_nx(self, entry):
        return False
        
    def is_accessed(self, entry):
        return entry & (1 << 5) == (1 << 5)
        
    def is_copyonwrite(self, entry):
        return entry & (1 << 9) == (1 << 9)

    def is_prototype(self, entry):
        return entry & (1 << 10) == (1 << 10)

    def pgd_index(self, pgd):
        return (pgd >> pgdir_shift) & (ptrs_per_pgd - 1)

    def get_pgd(self, vaddr):
        pgd_entry = self.dtb + self.pgd_index(vaddr) * pointer_size
        return self.read_long_phys(pgd_entry)

    def pte_pfn(self, pte):
        return pte >> page_shift

    def pte_index(self, pte):
        return (pte >> page_shift) & (ptrs_per_pte - 1)

    def get_pte(self, vaddr, pgd):
        pgd_val = pgd & ~((1 << page_shift) - 1)
        pgd_val = pgd_val + self.pte_index(vaddr) * pointer_size
        return self.read_long_phys(pgd_val)

    def get_paddr(self, vaddr, pte):
        return (self.pte_pfn(pte) << page_shift) | (vaddr & ((1 << page_shift) - 1))

    def get_four_meg_paddr(self, vaddr, pgd_entry):
        return (pgd_entry & ((ptrs_per_pgd - 1) << 22)) | (vaddr & ~((ptrs_per_pgd - 1) << 22))

    def vtop(self, vaddr):
        retVal = None
        pgd = self.get_pgd(vaddr)
        if self.entry_present(pgd):
            if self.page_size_flag(pgd):
                retVal = self.get_four_meg_paddr(vaddr, pgd)
            else:
                pte = self.get_pte(vaddr, pgd)
                if not pte:
                    return None
                if self.entry_present(pte):
                    retVal = self.get_paddr(vaddr, pte)
        return retVal

    def read_long_phys(self, addr):
        try:
            with open(self.image_path, 'r') as image:
                image.seek(addr)
                string = image.read(4)
                #print "read long phys", hex(addr), string
                #string = self.base.read(addr, 4)
        except IOError:
            string = None
        if not string:
            return obj.NoneObject("Unable to read_long_phys at " + hex(addr))
        longval, = self._long_struct.unpack(string)
        #print "longval", longval
        return longval

    def get_available_pages(self, with_pte = False):
        pgd_curr = self.dtb
        print "i386 get available page", hex(pgd_curr)
        for i in range(0, ptrs_per_pgd):
            start = (i * ptrs_per_pgd * ptrs_per_pte * 4)
            entry = self.read_long_phys(pgd_curr)
            pgd_curr = pgd_curr + 4
            if self.entry_present(entry) and self.page_size_flag(entry):
                if with_pte: 
                    yield (entry, start, 0x400000)
                else:
                    yield (start, 0x400000)
            elif self.entry_present(entry):
                pte_curr = entry & ~((1 << page_shift) - 1)
                for j in range(0, ptrs_per_pte):
                    pte_entry = self.read_long_phys(pte_curr)
                    pte_curr = pte_curr + 4
                    if self.entry_present(pte_entry):
                        if with_pte: 
                            yield (pte_entry, start + j * 0x1000, 0x1000)
                        else:
                            yield (start + j * 0x1000, 0x1000)
