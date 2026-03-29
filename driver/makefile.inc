$(OBJ_PATH)\$O\vmx_asm.obj: vmx_asm.asm
    ml64.exe /nologo /c /Fo$(OBJ_PATH)\$O\vmx_asm.obj vmx_asm.asm

$(OBJ_PATH)\$O\svm_asm.obj: svm_asm.asm
    ml64.exe /nologo /c /Fo$(OBJ_PATH)\$O\svm_asm.obj svm_asm.asm

$(OBJ_PATH)\$O\hv_hook_asm.obj: hv_hook_asm.asm
    ml64.exe /nologo /c /Fo$(OBJ_PATH)\$O\hv_hook_asm.obj hv_hook_asm.asm
