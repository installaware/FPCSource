{
    Copyright (c) 2025 by Free Pascal development team

    Support for ARM64/Win64 unwind data

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    See Microsoft ARM64 Exception Handling documentation for details.
}
unit win64unw;

{$i fpcdefs.inc}

interface

uses
  cclasses,globtype,aasmbase,aasmdata,aasmtai,cgbase,ogbase;

type
  TArm64WinCFI = class
  private
    FFrameOffs, FFrameReg: Integer;
    FFlags: Integer;
    FHandler: TObjSymbol;
    FCount: Integer;
    FElements: TLinkedList;
    FFrameStartSym: TObjSymbol;
    FFrameStartSec: TObjSection;
    FXdataSym: TObjSymbol;
    FXdataSec: TObjSection;
    FPrologueEndPos: aword;
    FPrologueEndSeen: Boolean;
    FName: pshortstring;
    procedure AddElement(objdata: TObjData; aCode, aInfo: Integer; aOpData: dword);
  public
    constructor Create;
    destructor Destroy; override;
    procedure GeneratePrologueData(objdata: TObjData);
    procedure StartFrame(objdata: TObjData; const name: string);
    procedure EndFrame(objdata: TObjData);
    procedure EndPrologue(objdata: TObjData);
    procedure SaveReg(objdata: TObjData; reg: tregister; ofs: dword);
    procedure SaveFReg(objdata: TObjData; reg: tregister; ofs: dword);
    procedure StackAlloc(objdata: TObjData; ofs: dword);
    procedure SetFrame(objdata: TObjData; reg: tregister; ofs: dword);
    procedure SwitchToHandlerData(objdata: TObjData);
  end;

var
  current_unw: TArm64WinCFI;

implementation

uses
  cutils,globals,verbose,cpubase;

{ ARM64 Unwind Codes - see MS documentation }
const
  UWOP_ALLOC_SMALL       = $01; // Alloc small stack, OpData = size/16 - 1
  UWOP_ALLOC_LARGE       = $02; // Alloc large stack, next slot = size
  UWOP_SAVE_REG          = $03; // Save integer reg, OpData = reg, next slot = offset
  UWOP_SAVE_REG_X        = $04; // Save integer reg, next slot = reg, next next slot = offset
  UWOP_SAVE_FREG         = $05; // Save FP reg, OpData = reg, next slot = offset
  UWOP_SAVE_FREG_X       = $06; // Save FP reg, next slot = reg, next next slot = offset
  UWOP_SET_FP            = $07; // Set frame pointer
  // More codes can be added as needed

type
  TPrologueElement = class(TLinkedListItem)
  public
    opcode: Byte;
    opdata: Byte;
    extra: word; // for offsets etc
  end;

var
  current_unw: TArm64WinCFI;

function EncodeARM64Reg(r: TRegister): Byte;
begin
  // Map FPC register enums to ARM64 register numbers, adjust as needed!
  case r of
    NR_X0:  result := 0;
    NR_X1:  result := 1;
    NR_X2:  result := 2;
    NR_X3:  result := 3;
    NR_X4:  result := 4;
    NR_X5:  result := 5;
    NR_X6:  result := 6;
    NR_X7:  result := 7;
    NR_X8:  result := 8;
    NR_X9:  result := 9;
    NR_X10: result := 10;
    NR_X11: result := 11;
    NR_X12: result := 12;
    NR_X13: result := 13;
    NR_X14: result := 14;
    NR_X15: result := 15;
    NR_X16: result := 16;
    NR_X17: result := 17;
    NR_X18: result := 18;
    NR_X19: result := 19;
    NR_X20: result := 20;
    NR_X21: result := 21;
    NR_X22: result := 22;
    NR_X23: result := 23;
    NR_X24: result := 24;
    NR_X25: result := 25;
    NR_X26: result := 26;
    NR_X27: result := 27;
    NR_X28: result := 28;
    NR_X29: result := 29;
    NR_X30: result := 30;
  else
    InternalError(2025092901); // Unknown register
  end;
end;

function EncodeARM64FReg(r: TRegister): Byte;
begin
  case r of
    NR_D0:  result := 0;
    NR_D1:  result := 1;
    NR_D2:  result := 2;
    NR_D3:  result := 3;
    NR_D4:  result := 4;
    NR_D5:  result := 5;
    NR_D6:  result := 6;
    NR_D7:  result := 7;
    NR_D8:  result := 8;
    NR_D9:  result := 9;
    NR_D10: result := 10;
    NR_D11: result := 11;
    NR_D12: result := 12;
    NR_D13: result := 13;
    NR_D14: result := 14;
    NR_D15: result := 15;
    NR_D16: result := 16;
    NR_D17: result := 17;
    NR_D18: result := 18;
    NR_D19: result := 19;
    NR_D20: result := 20;
    NR_D21: result := 21;
    NR_D22: result := 22;
    NR_D23: result := 23;
    NR_D24: result := 24;
    NR_D25: result := 25;
    NR_D26: result := 26;
    NR_D27: result := 27;
    NR_D28: result := 28;
    NR_D29: result := 29;
    NR_D30: result := 30;
    NR_D31: result := 31;
  else
    InternalError(2025092902); // Unknown FP register
  end;
end;

{ TArm64WinCFI }

constructor TArm64WinCFI.Create;
begin
  inherited Create;
  FElements := TLinkedList.Create;
end;

destructor TArm64WinCFI.Destroy;
begin
  FElements.Free;
  stringdispose(FName);
  inherited Destroy;
end;

procedure TArm64WinCFI.AddElement(objdata: TObjData; aCode, aInfo: Integer; aOpData: dword);
var
  el: TPrologueElement;
begin
  el := TPrologueElement.Create;
  FElements.concat(el);
  el.opcode := aCode;
  el.opdata := aInfo;
  el.extra := aOpData;
  Inc(FCount);
end;

procedure TArm64WinCFI.GeneratePrologueData(objdata: TObjData);
var
  hp: TPrologueElement;
  uwop: array [0..3] of byte;
  zero: word;
begin
  if codegenerror then
    exit;

  FXdataSec := objdata.createsection('.xdata.n_' + lower(FName^), 4, [oso_data, oso_load]);
  FXdataSym := objdata.symboldefine('$unwind$' + FName^, AB_GLOBAL, AT_DATA);

  // Write ARM64 UNWIND_INFO header (see MS documentation)
  uwop[0] := FFlags;
  uwop[1] := FPrologueEndPos - FFrameStartSym.address;
  uwop[2] := FCount;
  uwop[3] := FFrameReg;
  objdata.writebytes(uwop, 4);

  hp := TPrologueElement(FElements.First);
  while Assigned(hp) do
  begin
    objdata.writebytes(hp.opcode, 1);
    objdata.writebytes(hp.opdata, 1);
    objdata.writebytes(hp.extra, 2);
    hp := TPrologueElement(hp.Next);
  end;

  zero := 0;
  if odd(FCount) then
    objdata.writebytes(zero, 2);
  if Assigned(FHandler) then
    objdata.writereloc(0, sizeof(longint), FHandler, RELOC_RVA);
end;

procedure TArm64WinCFI.StartFrame(objdata: TObjData; const name: string);
begin
  if assigned(FName) then
    internalerror(2025092903);
  FName := stringdup(name);
  FFrameStartSym := objdata.symbolref(name);
  FFrameStartSec := objdata.CurrObjSec;
  FCount := 0;
  FFrameReg := 0;
  FFrameOffs := 0;
  FPrologueEndPos := 0;
  FPrologueEndSeen := false;
  FHandler := nil;
  FXdataSec := nil;
  FXdataSym := nil;
  FFlags := 0;
end;

procedure TArm64WinCFI.EndFrame(objdata: TObjData);
var
  pdatasec: TObjSection;
begin
  if not assigned(FName) then
    internalerror(2025092904);

  if FXdataSec = nil then
    GeneratePrologueData(objdata);

  if not codegenerror then
  begin
    pdatasec := objdata.createsection(sec_pdata, lower(FName^));
    objdata.writereloc(0, 4, FFrameStartSym, RELOC_RVA);
    objdata.writereloc(FFrameStartSec.Size, 4, FFrameStartSym, RELOC_RVA);
    objdata.writereloc(0, 4, FXdataSym, RELOC_RVA);
    objdata.SetSection(FFrameStartSec);
    FFrameStartSec.AddSectionReloc(0, pdatasec, RELOC_NONE);
  end;
  FElements.Clear;
  FFrameStartSym := nil;
  FHandler := nil;
  FXdataSec := nil;
  FXdataSym := nil;
  FFlags := 0;
  stringdispose(FName);
end;

procedure TArm64WinCFI.EndPrologue(objdata: TObjData);
begin
  if not assigned(FName) then
    internalerror(2025092905);
  FPrologueEndPos := objdata.CurrObjSec.Size;
  FPrologueEndSeen := true;
end;

procedure TArm64WinCFI.SaveReg(objdata: TObjData; reg: tregister; ofs: dword);
var
  info: Byte;
begin
  info := EncodeARM64Reg(reg);
  AddElement(objdata, UWOP_SAVE_REG, info, ofs);
end;

procedure TArm64WinCFI.SaveFReg(objdata: TObjData; reg: tregister; ofs: dword);
var
  info: Byte;
begin
  info := EncodeARM64FReg(reg);
  AddElement(objdata, UWOP_SAVE_FREG, info, ofs);
end;

procedure TArm64WinCFI.StackAlloc(objdata: TObjData; ofs: dword);
begin
  if ofs <= 512 then
    AddElement(objdata, UWOP_ALLOC_SMALL, ((ofs div 16) - 1), 0)
  else
    AddElement(objdata, UWOP_ALLOC_LARGE, 0, ofs);
end;

procedure TArm64WinCFI.SetFrame(objdata: TObjData; reg: tregister; ofs: dword);
var
  info: Byte;
begin
  info := EncodeARM64Reg(reg);
  FFrameReg := info;
  FFrameOffs := ofs;
  AddElement(objdata, UWOP_SET_FP, info, ofs);
end;

procedure TArm64WinCFI.SwitchToHandlerData(objdata: TObjData);
begin
  if not assigned(FName) then
    internalerror(2025092906);

  if FHandler = nil then
    CGMessage(asmw_e_handlerdata_no_handler);

  if FXdataSec = nil then
    GeneratePrologueData(objdata)
  else
    objdata.SetSection(FXdataSec);
end;

initialization
  current_unw := TArm64WinCFI.Create;
finalization
  current_unw.Free;
end.
