$(OBJ_PATH)\$(O)\ipipnic.mof: ipipnic.mof

$(OBJ_PATH)\$(O)\mof.h: $(OBJ_PATH)\$(O)\ipipnic.bmf 
    wmimofck -h$(OBJ_PATH)\$(O)\mof.h $(OBJ_PATH)\$(O)\ipipnic.bmf
