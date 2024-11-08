#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

include $(SGX_SDK)/buildenv.mk

ifeq ($(shell getconf LONG_BIT), 32)
    SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
    SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
    SGX_COMMON_FLAGS := -m32
    SGX_LIBRARY_PATH := $(SGX_SDK)/lib
    SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
    SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
    SGX_COMMON_FLAGS := -m64
    SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
    SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
    SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_FLAGS += -O0 -g
else
        SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
# SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
# SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

######## App Settings ########

ifneq ($(SGX_MODE), HW)
    Urts_Library_Name := sgx_urts_sim
else
    Urts_Library_Name := sgx_urts
endif

App_Cpp_Files := App/App.cpp $(wildcard App/Edger8rSyntax/*.cpp) $(wildcard App/TrustedLibrary/*.cpp)
App_Include_Paths := -IApp -I$(SGX_SDK)/include


App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) # -std=c++11
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread 

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := app

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
    Trts_Library_Name := sgx_trts_sim
    Service_Library_Name := sgx_tservice_sim
else
    Trts_Library_Name := sgx_trts
    Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := Enclave/Enclave.cpp $(wildcard Enclave/Edger8rSyntax/*.cpp) $(wildcard Enclave/TrustedLibrary/*.cpp)
Enclave_Include_Paths := -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx


Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector 

Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++

# Enable the security flags
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(MITIGATION_LDFLAGS) $(Enclave_Security_Link_Flags) \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_TRUSTED_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	# -Wl,--version-script=Enclave/Enclave.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml
Enclave_Test_Key := Enclave/Enclave_private_test.pem

######## Initiator Enclave Settings ########

Initiator_Enclave_Cpp_Files := Initiator_Enclave/Initiator_Enclave.cpp 
Initiator_Enclave_Include_Paths := -IInitiator_Enclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx 


Initiator_Enclave_C_Flags := $(Initiator_Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector 

Initiator_Enclave_Cpp_Flags := $(Initiator_Enclave_C_Flags) -nostdinc++ # -std=c++11

Initiator_Enclave_Link_Flags := $(MITIGATION_LDFLAGS) $(Enclave_Security_Link_Flags) \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_TRUSTED_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	# -Wl,--version-script=Enclave/Enclave.lds

Initiator_Enclave_Cpp_Objects := $(Initiator_Enclave_Cpp_Files:.cpp=.o)

Initiator_Enclave_Name := initiator_enclave.so
Initiator_Signed_Enclave_Name := initiator_enclave.signed.so
Initiator_Enclave_Config_File := Initiator_Enclave/Enclave.config.xml
Initiator_Enclave_Test_Key := Initiator_Enclave/Initiator_Enclave_private_test.pem

######## Responder Enclave Settings ########

Responder_Enclave_Cpp_Files := Responder_Enclave/Responder_Enclave.cpp 
Responder_Enclave_Include_Paths := -IResponder_Enclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx 


Responder_Enclave_C_Flags := $(Responder_Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections $(MITIGATION_CFLAGS)

Responder_Enclave_Cpp_Flags := $(Responder_Enclave_C_Flags) -nostdinc++ # -std=c++11

Responder_Enclave_Link_Flags := $(MITIGATION_LDFLAGS) $(Enclave_Security_Link_Flags) \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_TRUSTED_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	# -Wl,--version-script=Enclave/Enclave.lds

Responder_Enclave_Cpp_Objects := $(Responder_Enclave_Cpp_Files:.cpp=.o)

Responder_Enclave_Name := responder_enclave.so
Responder_Signed_Enclave_Name := responder_enclave.signed.so
Responder_Enclave_Config_File := Responder_Enclave/Enclave.config.xml
Responder_Enclave_Test_Key := Responder_Enclave/Responder_Enclave_private_test.pem

######## Build Flag Settings ########

ifeq ($(SGX_MODE), HW)
	ifneq ($(SGX_DEBUG), 1)
		ifneq ($(SGX_PRERELEASE), 1)
    		Build_Mode = HW_RELEASE
		endif
	endif
endif

######## Make Command Settings ########

.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all:  $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App_Name) $(Signed_Enclave_Name) $(Initiator_Signed_Enclave_Name) $(Responder_Signed_Enclave_Name)
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########

App/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

App/Initiator_Enclave_u.c: $(SGX_EDGER8R) Initiator_Enclave/Initiator_Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Initiator_Enclave/Initiator_Enclave.edl --search-path ../Initiator_Enclave --search-path $(SGX_SDK)/include
	
App/Responder_Enclave_u.c: $(SGX_EDGER8R) Responder_Enclave/Responder_Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Responder_Enclave/Responder_Enclave.edl --search-path ../Responder_Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

App/Enclave_u.o: App/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/Initiator_Enclave_u.o: App/Initiator_Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/Responder_Enclave_u.o: App/Responder_Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): App/Enclave_u.o App/Initiator_Enclave_u.o App/Responder_Enclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

Enclave/Enclave_t.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
ifeq ($(wildcard $(Enclave_Test_Key)),)
	@echo "There is no enclave test key<Enclave_private_test.pem>."
	@echo "The project will generate a key<Enclave_private_test.pem> for test."
	@openssl genrsa -out $(Enclave_Test_Key) -3 3072
endif
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Test_Key) -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

######## Initiator Enclave Objects ########

Initiator_Enclave/Initiator_Enclave_t.c: $(SGX_EDGER8R) Initiator_Enclave/Initiator_Enclave.edl
	@cd Initiator_Enclave && $(SGX_EDGER8R) --trusted ../Initiator_Enclave/Initiator_Enclave.edl --search-path ../Initiator_Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Initiator_Enclave/Initiator_Enclave_t.o: Initiator_Enclave/Initiator_Enclave_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Initiator_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Initiator_Enclave/%.o: Initiator_Enclave/%.cpp
	@$(CXX) $(Initiator_Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Initiator_Enclave_Name): Initiator_Enclave/Initiator_Enclave_t.o $(Initiator_Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Initiator_Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Initiator_Signed_Enclave_Name): $(Initiator_Enclave_Name)
ifeq ($(wildcard $(Initiator_Enclave_Test_Key)),)
	@echo "There is no enclave test key<Initiator_Enclave_private_test.pem>."
	@echo "The project will generate a key<Initiator_Enclave_private_test.pem> for test."
	@openssl genrsa -out $(Initiator_Enclave_Test_Key) -3 3072
endif
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Initiator_Enclave_Test_Key) -enclave $(Initiator_Enclave_Name) -out $@ -config $(Initiator_Enclave_Config_File)
	@echo "SIGN =>  $@"

######## Responder Enclave Objects ########

Responder_Enclave/Responder_Enclave_t.c: $(SGX_EDGER8R) Responder_Enclave/Responder_Enclave.edl
	@cd Responder_Enclave && $(SGX_EDGER8R) --trusted ../Responder_Enclave/Responder_Enclave.edl --search-path ../Responder_Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Responder_Enclave/Responder_Enclave_t.o: Responder_Enclave/Responder_Enclave_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Responder_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Responder_Enclave/%.o: Responder_Enclave/%.cpp
	@$(CXX) $(Responder_Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Responder_Enclave_Name): Responder_Enclave/Responder_Enclave_t.o $(Responder_Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Responder_Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Responder_Signed_Enclave_Name): $(Responder_Enclave_Name)
ifeq ($(wildcard $(Responder_Enclave_Test_Key)),)
	@echo "There is no enclave test key<Responder_Enclave_private_test.pem>."
	@echo "The project will generate a key<Responder_Enclave_private_test.pem> for test."
	@openssl genrsa -out $(Responder_Enclave_Test_Key) -3 3072
endif
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Responder_Enclave_Test_Key) -enclave $(Responder_Enclave_Name) -out $@ -config $(Responder_Enclave_Config_File)
	@echo "SIGN =>  $@"


.PHONY: clean

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.* 
	@rm -f $(Initiator_Enclave_Name) $(Initiator_Signed_Enclave_Name) App/Initiator_Enclave_u.* $(Initiator_Enclave_Cpp_Objects) Initiator_Enclave/Initiator_Enclave_t.*
	@rm -f $(Responder_Enclave_Name) $(Responder_Signed_Enclave_Name) App/Responder_Enclave_u.* $(Responder_Enclave_Cpp_Objects) Responder_Enclave/Responder_Enclave_t.*

