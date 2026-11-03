/* SPDX-License-Identifier: LGPL-2.0-or-later */
#include "ck_fs_tree.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
_Static_assert(sizeof(ckfet_name_feedback_v1)==112,"additive name feedback size");
_Static_assert(offsetof(ckfet_name_feedback_v1,choice)==40,"choice offset");
_Static_assert(offsetof(ckfet_name_feedback_v1,reserved3)==104,"reserve offset");
_Static_assert(sizeof(ckfet_row_v1)==280,"unchanged v1 row ABI");
int main(void){ckfet_name_feedback_v1 out;memset(&out,0x55,sizeof(out));assert(ckfet_name_feedback_get_v1(NULL,1,1,CKFET_NAME_CHOICE_SELECTED,&out)==CKFE_API_INVALID_ARGUMENT);for(size_t i=0;i<sizeof(out);++i)assert(((unsigned char*)&out)[i]==0);printf("strict C11 linked getter and unchanged row v1: %zu\n",sizeof(ckfet_row_v1));return 0;}
