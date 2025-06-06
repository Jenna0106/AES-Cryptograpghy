module AES_Encrypt (
    input wire start,           // Start signal to enable encryption
    input wire [127:0] in,      // Plaintext input
    output wire [127:0] out,    // Ciphertext output
    output wire done_encr        // Done signal indicating encryption completion
);

localparam [127:0] FIXED_KEY = 128'h000102030405060708090a0b0c0d0e0f;
wire [1407:0] fullkeys;
wire [127:0] states [11:0];
wire [127:0] afterSubBytes;
wire [127:0] afterShiftRows;

key_expansion ke (FIXED_KEY,fullkeys);

addRoundKey addrk1(in,states[0],fullkeys[1407-:128]);

genvar i;
generate
	
	for(i=1; i<10 ;i=i+1)begin : loop
		encryptRound er(states[i-1],fullkeys[(1407-(128*i))-:128],states[i]);
	end

endgenerate

sub_bytes sb(states[9],afterSubBytes);
shift_rows sr(afterSubBytes,afterShiftRows);
addRoundKey addrk2(afterShiftRows,states[10],fullkeys[127:0]);


// Output logic: only valid when start is high
    assign out = start ? states[10] : 128'b0; // Output is zero unless start is high
    assign done_encr = start;                  // Done immediately when start is high (combinatorial)

endmodule

module addRoundKey(data, out, key);

input [127:0] data;
input [127:0] key;
output [127:0] out;

assign out = key ^ data;

endmodule

module encryptRound(in,key,out);
input [127:0] in;
output [127:0] out;
input [127:0] key;
wire [127:0] afterSubBytes;
wire [127:0] afterShiftRows;
wire [127:0] afterMixColumns;
wire [127:0] afterAddroundKey;

sub_bytes s(in,afterSubBytes);
shift_rows r(afterSubBytes,afterShiftRows);
mixColumns m(afterShiftRows,afterMixColumns);
addRoundKey b(afterMixColumns,out,key);
		
endmodule

module mixColumns(state_in,state_out);

input [127:0] state_in;
output[127:0] state_out;


function [7:0] mb2; //multiply by 2
	input [7:0] x;
	begin 
			if(x[7] == 1) mb2 = ((x << 1) ^ 8'h1b);
			else mb2 = x << 1; 
	end 	
endfunction

function [7:0] mb3; //multiply by 3
	input [7:0] x;
	begin 
			
			mb3 = mb2(x) ^ x;
	end 
endfunction

genvar i;

generate 
for(i=0;i< 4;i=i+1) begin : m_col

	assign state_out[(i*32 + 24)+:8]= mb2(state_in[(i*32 + 24)+:8]) ^ mb3(state_in[(i*32 + 16)+:8]) ^ state_in[(i*32 + 8)+:8] ^ state_in[i*32+:8];
	assign state_out[(i*32 + 16)+:8]= state_in[(i*32 + 24)+:8] ^ mb2(state_in[(i*32 + 16)+:8]) ^ mb3(state_in[(i*32 + 8)+:8]) ^ state_in[i*32+:8];
	assign state_out[(i*32 + 8)+:8]= state_in[(i*32 + 24)+:8] ^ state_in[(i*32 + 16)+:8] ^ mb2(state_in[(i*32 + 8)+:8]) ^ mb3(state_in[i*32+:8]);
   assign state_out[i*32+:8]= mb3(state_in[(i*32 + 24)+:8]) ^ state_in[(i*32 + 16)+:8] ^ state_in[(i*32 + 8)+:8] ^ mb2(state_in[i*32+:8]);

end

endgenerate

endmodule

module sub_bytes(in,out);
input [127:0] in;
output [127:0] out;

genvar i;
generate 
for(i=0;i<128;i=i+8) begin :sub_Bytes 
	sbox s(in[i +:8],out[i +:8]);
	end
endgenerate

endmodule


module shift_rows(in, shifted);
	input [0:127] in;
	output [0:127] shifted;
	
	// First row 
	assign shifted[0+:8] = in[0+:8];
	assign shifted[32+:8] = in[32+:8];
	assign shifted[64+:8] = in[64+:8];
   assign shifted[96+:8] = in[96+:8];
	
	// Second row 
   assign shifted[8+:8] = in[40+:8];
   assign shifted[40+:8] = in[72+:8];
   assign shifted[72+:8] = in[104+:8];
   assign shifted[104+:8] = in[8+:8];
	
	// Third row 
   assign shifted[16+:8] = in[80+:8];
   assign shifted[48+:8] = in[112+:8];
   assign shifted[80+:8] = in[16+:8];
   assign shifted[112+:8] = in[48+:8];
	
	// Fourth row 
   assign shifted[24+:8] = in[120+:8];
   assign shifted[56+:8] = in[24+:8];
   assign shifted[88+:8] = in[56+:8];
   assign shifted[120+:8] = in[88+:8];

endmodule




module sbox(a,c);

input  [7:0] a; 
output [7:0] c;
    
reg [7:0] c;
    
    
   always @(a)
    case (a)
      8'h00: c=8'h63;
	   8'h01: c=8'h7c;
	   8'h02: c=8'h77;
	   8'h03: c=8'h7b;
	   8'h04: c=8'hf2;
	   8'h05: c=8'h6b;
	   8'h06: c=8'h6f;
	   8'h07: c=8'hc5;
	   8'h08: c=8'h30;
	   8'h09: c=8'h01;
	   8'h0a: c=8'h67;
	   8'h0b: c=8'h2b;
	   8'h0c: c=8'hfe;
	   8'h0d: c=8'hd7;
	   8'h0e: c=8'hab;
	   8'h0f: c=8'h76;
	   8'h10: c=8'hca;
	   8'h11: c=8'h82;
	   8'h12: c=8'hc9;
	   8'h13: c=8'h7d;
	   8'h14: c=8'hfa;
	   8'h15: c=8'h59;
	   8'h16: c=8'h47;
	   8'h17: c=8'hf0;
	   8'h18: c=8'had;
	   8'h19: c=8'hd4;
	   8'h1a: c=8'ha2;
	   8'h1b: c=8'haf;
	   8'h1c: c=8'h9c;
	   8'h1d: c=8'ha4;
	   8'h1e: c=8'h72;
	   8'h1f: c=8'hc0;
	   8'h20: c=8'hb7;
	   8'h21: c=8'hfd;
	   8'h22: c=8'h93;
	   8'h23: c=8'h26;
	   8'h24: c=8'h36;
	   8'h25: c=8'h3f;
	   8'h26: c=8'hf7;
	   8'h27: c=8'hcc;
	   8'h28: c=8'h34;
	   8'h29: c=8'ha5;
	   8'h2a: c=8'he5;
	   8'h2b: c=8'hf1;
	   8'h2c: c=8'h71;
	   8'h2d: c=8'hd8;
	   8'h2e: c=8'h31;
	   8'h2f: c=8'h15;
	   8'h30: c=8'h04;
	   8'h31: c=8'hc7;
	   8'h32: c=8'h23;
	   8'h33: c=8'hc3;
	   8'h34: c=8'h18;
	   8'h35: c=8'h96;
	   8'h36: c=8'h05;
	   8'h37: c=8'h9a;
	   8'h38: c=8'h07;
	   8'h39: c=8'h12;
	   8'h3a: c=8'h80;
	   8'h3b: c=8'he2;
	   8'h3c: c=8'heb;
	   8'h3d: c=8'h27;
	   8'h3e: c=8'hb2;
	   8'h3f: c=8'h75;
	   8'h40: c=8'h09;
	   8'h41: c=8'h83;
	   8'h42: c=8'h2c;
	   8'h43: c=8'h1a;
	   8'h44: c=8'h1b;
	   8'h45: c=8'h6e;
	   8'h46: c=8'h5a;
	   8'h47: c=8'ha0;
	   8'h48: c=8'h52;
	   8'h49: c=8'h3b;
	   8'h4a: c=8'hd6;
	   8'h4b: c=8'hb3;
	   8'h4c: c=8'h29;
	   8'h4d: c=8'he3;
	   8'h4e: c=8'h2f;
	   8'h4f: c=8'h84;
	   8'h50: c=8'h53;
	   8'h51: c=8'hd1;
	   8'h52: c=8'h00;
	   8'h53: c=8'hed;
	   8'h54: c=8'h20;
	   8'h55: c=8'hfc;
	   8'h56: c=8'hb1;
	   8'h57: c=8'h5b;
	   8'h58: c=8'h6a;
	   8'h59: c=8'hcb;
	   8'h5a: c=8'hbe;
	   8'h5b: c=8'h39;
	   8'h5c: c=8'h4a;
	   8'h5d: c=8'h4c;
	   8'h5e: c=8'h58;
	   8'h5f: c=8'hcf;
	   8'h60: c=8'hd0;
	   8'h61: c=8'hef;
	   8'h62: c=8'haa;
	   8'h63: c=8'hfb;
	   8'h64: c=8'h43;
	   8'h65: c=8'h4d;
	   8'h66: c=8'h33;
	   8'h67: c=8'h85;
	   8'h68: c=8'h45;
	   8'h69: c=8'hf9;
	   8'h6a: c=8'h02;
	   8'h6b: c=8'h7f;
	   8'h6c: c=8'h50;
	   8'h6d: c=8'h3c;
	   8'h6e: c=8'h9f;
	   8'h6f: c=8'ha8;
	   8'h70: c=8'h51;
	   8'h71: c=8'ha3;
	   8'h72: c=8'h40;
	   8'h73: c=8'h8f;
	   8'h74: c=8'h92;
	   8'h75: c=8'h9d;
	   8'h76: c=8'h38;
	   8'h77: c=8'hf5;
	   8'h78: c=8'hbc;
	   8'h79: c=8'hb6;
	   8'h7a: c=8'hda;
	   8'h7b: c=8'h21;
	   8'h7c: c=8'h10;
	   8'h7d: c=8'hff;
	   8'h7e: c=8'hf3;
	   8'h7f: c=8'hd2;
	   8'h80: c=8'hcd;
	   8'h81: c=8'h0c;
	   8'h82: c=8'h13;
	   8'h83: c=8'hec;
	   8'h84: c=8'h5f;
	   8'h85: c=8'h97;
	   8'h86: c=8'h44;
	   8'h87: c=8'h17;
	   8'h88: c=8'hc4;
	   8'h89: c=8'ha7;
	   8'h8a: c=8'h7e;
	   8'h8b: c=8'h3d;
	   8'h8c: c=8'h64;
	   8'h8d: c=8'h5d;
	   8'h8e: c=8'h19;
	   8'h8f: c=8'h73;
	   8'h90: c=8'h60;
	   8'h91: c=8'h81;
	   8'h92: c=8'h4f;
	   8'h93: c=8'hdc;
	   8'h94: c=8'h22;
	   8'h95: c=8'h2a;
	   8'h96: c=8'h90;
	   8'h97: c=8'h88;
	   8'h98: c=8'h46;
	   8'h99: c=8'hee;
	   8'h9a: c=8'hb8;
	   8'h9b: c=8'h14;
	   8'h9c: c=8'hde;
	   8'h9d: c=8'h5e;
	   8'h9e: c=8'h0b;
	   8'h9f: c=8'hdb;
	   8'ha0: c=8'he0;
	   8'ha1: c=8'h32;
	   8'ha2: c=8'h3a;
	   8'ha3: c=8'h0a;
	   8'ha4: c=8'h49;
	   8'ha5: c=8'h06;
	   8'ha6: c=8'h24;
	   8'ha7: c=8'h5c;
	   8'ha8: c=8'hc2;
	   8'ha9: c=8'hd3;
	   8'haa: c=8'hac;
	   8'hab: c=8'h62;
	   8'hac: c=8'h91;
	   8'had: c=8'h95;
	   8'hae: c=8'he4;
	   8'haf: c=8'h79;
	   8'hb0: c=8'he7;
	   8'hb1: c=8'hc8;
	   8'hb2: c=8'h37;
	   8'hb3: c=8'h6d;
	   8'hb4: c=8'h8d;
	   8'hb5: c=8'hd5;
	   8'hb6: c=8'h4e;
	   8'hb7: c=8'ha9;
	   8'hb8: c=8'h6c;
	   8'hb9: c=8'h56;
	   8'hba: c=8'hf4;
	   8'hbb: c=8'hea;
	   8'hbc: c=8'h65;
	   8'hbd: c=8'h7a;
	   8'hbe: c=8'hae;
	   8'hbf: c=8'h08;
	   8'hc0: c=8'hba;
	   8'hc1: c=8'h78;
	   8'hc2: c=8'h25;
	   8'hc3: c=8'h2e;
	   8'hc4: c=8'h1c;
	   8'hc5: c=8'ha6;
	   8'hc6: c=8'hb4;
	   8'hc7: c=8'hc6;
	   8'hc8: c=8'he8;
	   8'hc9: c=8'hdd;
	   8'hca: c=8'h74;
	   8'hcb: c=8'h1f;
	   8'hcc: c=8'h4b;
	   8'hcd: c=8'hbd;
	   8'hce: c=8'h8b;
	   8'hcf: c=8'h8a;
	   8'hd0: c=8'h70;
	   8'hd1: c=8'h3e;
	   8'hd2: c=8'hb5;
	   8'hd3: c=8'h66;
	   8'hd4: c=8'h48;
	   8'hd5: c=8'h03;
	   8'hd6: c=8'hf6;
	   8'hd7: c=8'h0e;
	   8'hd8: c=8'h61;
	   8'hd9: c=8'h35;
	   8'hda: c=8'h57;
	   8'hdb: c=8'hb9;
	   8'hdc: c=8'h86;
	   8'hdd: c=8'hc1;
	   8'hde: c=8'h1d;
	   8'hdf: c=8'h9e;
	   8'he0: c=8'he1;
	   8'he1: c=8'hf8;
	   8'he2: c=8'h98;
	   8'he3: c=8'h11;
	   8'he4: c=8'h69;
	   8'he5: c=8'hd9;
	   8'he6: c=8'h8e;
	   8'he7: c=8'h94;
	   8'he8: c=8'h9b;
	   8'he9: c=8'h1e;
	   8'hea: c=8'h87;
	   8'heb: c=8'he9;
	   8'hec: c=8'hce;
	   8'hed: c=8'h55;
	   8'hee: c=8'h28;
	   8'hef: c=8'hdf;
	   8'hf0: c=8'h8c;
	   8'hf1: c=8'ha1;
	   8'hf2: c=8'h89;
	   8'hf3: c=8'h0d;
	   8'hf4: c=8'hbf;
	   8'hf5: c=8'he6;
	   8'hf6: c=8'h42;
	   8'hf7: c=8'h68;
	   8'hf8: c=8'h41;
	   8'hf9: c=8'h99;
	   8'hfa: c=8'h2d;
	   8'hfb: c=8'h0f;
	   8'hfc: c=8'hb0;
	   8'hfd: c=8'h54;
	   8'hfe: c=8'hbb;
	   8'hff: c=8'h16;
	endcase

endmodule

module key_expansion(
    input [127:0] key_in,
    output reg [1407:0] round_keys 
);

    reg [31:0] w [0:43];
    integer i;

    // Rcon array
    reg [31:0] Rcon [0:10];
    initial begin
        Rcon[0] = 32'h01000000;
        Rcon[1] = 32'h02000000;
        Rcon[2] = 32'h04000000;
        Rcon[3] = 32'h08000000;
        Rcon[4] = 32'h10000000;
        Rcon[5] = 32'h20000000;
        Rcon[6] = 32'h40000000;
        Rcon[7] = 32'h80000000;
        Rcon[8] = 32'h1b000000;
        Rcon[9] = 32'h36000000;
    end

    // S-Box array definition
    reg [7:0] sbox [0:255];
    initial begin
       sbox[  0] = 8'h63; sbox[  1] = 8'h7c; sbox[  2] = 8'h77; sbox[  3] = 8'h7b; //row0
        sbox[  4] = 8'hf2; sbox[  5] = 8'h6b; sbox[  6] = 8'h6f; sbox[  7] = 8'hc5;
        sbox[  8] = 8'h30; sbox[  9] = 8'h01; sbox[ 10] = 8'h67; sbox[ 11] = 8'h2b;
        sbox[ 12] = 8'hfe; sbox[ 13] = 8'hd7; sbox[ 14] = 8'hab; sbox[ 15] = 8'h76;

        sbox[ 16] = 8'hca; sbox[ 17] = 8'h82; sbox[ 18] = 8'hc9; sbox[ 19] = 8'h7d;//row1
        sbox[ 20] = 8'hfa; sbox[ 21] = 8'h59; sbox[ 22] = 8'h47; sbox[ 23] = 8'hf0;
        sbox[ 24] = 8'had; sbox[ 25] = 8'hd4; sbox[ 26] = 8'ha2; sbox[ 27] = 8'haf;
        sbox[ 28] = 8'h9c; sbox[ 29] = 8'ha4; sbox[ 30] = 8'h72; sbox[ 31] = 8'hc0;

        sbox[ 32] = 8'hb7; sbox[ 33] = 8'hfd; sbox[ 34] = 8'h93; sbox[ 35] = 8'h26;//row2
        sbox[ 36] = 8'h36; sbox[ 37] = 8'h3f; sbox[ 38] = 8'hf7; sbox[ 39] = 8'hcc;
        sbox[ 40] = 8'h34; sbox[ 41] = 8'ha5; sbox[ 42] = 8'he5; sbox[ 43] = 8'hf1;
        sbox[ 44] = 8'h71; sbox[ 45] = 8'hd8; sbox[ 46] = 8'h31; sbox[ 47] = 8'h15;

        sbox[ 48] = 8'h04; sbox[ 49] = 8'hc7; sbox[ 50] = 8'h23; sbox[ 51] = 8'hc3;//row3
        sbox[ 52] = 8'h18; sbox[ 53] = 8'h96; sbox[ 54] = 8'h05; sbox[ 55] = 8'h9a;
        sbox[ 56] = 8'h07; sbox[ 57] = 8'h12; sbox[ 58] = 8'h80; sbox[ 59] = 8'he2;
        sbox[ 60] = 8'heb; sbox[ 61] = 8'h27; sbox[ 62] = 8'hb2; sbox[ 63] = 8'h75;

        sbox[ 64] = 8'h09; sbox[ 65] = 8'h83; sbox[ 66] = 8'h2c; sbox[ 67] = 8'h1a;//row4
        sbox[ 68] = 8'h1b; sbox[ 69] = 8'h6e; sbox[ 70] = 8'h5a; sbox[ 71] = 8'ha0;
        sbox[ 72] = 8'h52; sbox[ 73] = 8'h3b; sbox[ 74] = 8'hd6; sbox[ 75] = 8'hb3;
        sbox[ 76] = 8'h29; sbox[ 77] = 8'he3; sbox[ 78] = 8'h2f; sbox[ 79] = 8'h84;

        sbox[ 80] = 8'h53; sbox[ 81] = 8'hd1; sbox[ 82] = 8'h00; sbox[ 83] = 8'hed;//row5
        sbox[ 84] = 8'h20; sbox[ 85] = 8'hfc; sbox[ 86] = 8'hb1; sbox[ 87] = 8'h5b;
        sbox[ 88] = 8'h6a; sbox[ 89] = 8'hcb; sbox[ 90] = 8'hbe; sbox[ 91] = 8'h39;
        sbox[ 92] = 8'h4a; sbox[ 93] = 8'h4c; sbox[ 94] = 8'h58; sbox[ 95] = 8'hcf;
        
        sbox[ 96] = 8'hd0; sbox[ 97] = 8'hef; sbox[ 98] = 8'haa; sbox[ 99] = 8'hfd;//row6
        sbox[100] = 8'h43; sbox[101] = 8'h4d; sbox[102] = 8'h33; sbox[103] = 8'h85;
        sbox[104] = 8'h45; sbox[105] = 8'hf9; sbox[106] = 8'h02; sbox[107] = 8'h7f;
        sbox[108] = 8'h50; sbox[109] = 8'h3c; sbox[110] = 8'h9f; sbox[111] = 8'ha8;
        
        sbox[112] = 8'h51; sbox[113] = 8'ha3; sbox[114] = 8'h40; sbox[115] = 8'h8f;//row7
        sbox[116] = 8'h92; sbox[117] = 8'h9d; sbox[118] = 8'h38; sbox[119] = 8'hf5;
        sbox[120] = 8'hbc; sbox[121] = 8'hb6; sbox[122] = 8'hda; sbox[123] = 8'h21;
        sbox[124] = 8'h10; sbox[125] = 8'hff; sbox[126] = 8'hf3; sbox[127] = 8'hd2;

        sbox[128] = 8'hcd; sbox[129] = 8'h0c; sbox[130] = 8'h13; sbox[131] = 8'hec;//row8
        sbox[132] = 8'h5f; sbox[133] = 8'h97; sbox[134] = 8'h44; sbox[135] = 8'h17;
        sbox[136] = 8'hc4; sbox[137] = 8'ha7; sbox[138] = 8'h7e; sbox[139] = 8'h3d;
        sbox[140] = 8'h64; sbox[141] = 8'h5d; sbox[142] = 8'h19; sbox[143] = 8'h73;

        sbox[144] = 8'h60; sbox[145] = 8'h81; sbox[146] = 8'h4f; sbox[147] = 8'hdc;//row9
        sbox[148] = 8'h22; sbox[149] = 8'h2a; sbox[150] = 8'h90; sbox[151] = 8'h88;
        sbox[152] = 8'h46; sbox[153] = 8'hee; sbox[154] = 8'hb8; sbox[155] = 8'h14;
        sbox[156] = 8'hde; sbox[157] = 8'h5e; sbox[158] = 8'h0b; sbox[159] = 8'hdb;
        
        sbox[160] = 8'he0; sbox[161] = 8'h32; sbox[162] = 8'h3a; sbox[163] = 8'h0a;//row10 (A)
        sbox[164] = 8'h49; sbox[165] = 8'h06; sbox[166] = 8'h24; sbox[167] = 8'h5c;
        sbox[168] = 8'hc2; sbox[169] = 8'hd3; sbox[170] = 8'hac; sbox[171] = 8'h62;
        sbox[172] = 8'h91; sbox[173] = 8'h95; sbox[174] = 8'he4; sbox[175] = 8'h79;

        sbox[176] = 8'he7; sbox[177] = 8'hc8; sbox[178] = 8'h37; sbox[179] = 8'h6d;//row11 (B)
        sbox[180] = 8'h8d; sbox[181] = 8'hd5; sbox[182] = 8'h4e; sbox[183] = 8'ha9;
        sbox[184] = 8'h6c; sbox[185] = 8'h56; sbox[186] = 8'hf4; sbox[187] = 8'hea;
        sbox[188] = 8'h65; sbox[189] = 8'h7a; sbox[190] = 8'hae; sbox[191] = 8'h08;

        sbox[192] = 8'hba; sbox[193] = 8'h78; sbox[194] = 8'h25; sbox[195] = 8'h2e;//row12 (C)
        sbox[196] = 8'h1c; sbox[197] = 8'ha6; sbox[198] = 8'hb4; sbox[199] = 8'hc6;
        sbox[200] = 8'he8; sbox[201] = 8'hdd; sbox[202] = 8'h74; sbox[203] = 8'h1f;
        sbox[204] = 8'h4b; sbox[205] = 8'hbd; sbox[206] = 8'h8b; sbox[207] = 8'h8a;

        sbox[208] = 8'h70; sbox[209] = 8'h3e; sbox[210] = 8'hb5; sbox[211] = 8'h66;//row13 (D)
        sbox[212] = 8'h48; sbox[213] = 8'h03; sbox[214] = 8'hf6; sbox[215] = 8'h0e;
        sbox[216] = 8'h61; sbox[217] = 8'h35; sbox[218] = 8'h57; sbox[219] = 8'hb9;
        sbox[220] = 8'h86; sbox[221] = 8'hc1; sbox[222] = 8'h1d; sbox[223] = 8'h9e;

        sbox[224] = 8'he1; sbox[225] = 8'hf8; sbox[226] = 8'h98; sbox[227] = 8'h11;//row14 (E)
        sbox[228] = 8'h69; sbox[229] = 8'hd9; sbox[230] = 8'h8e; sbox[231] = 8'h94;
        sbox[232] = 8'h9b; sbox[233] = 8'h1e; sbox[234] = 8'h87; sbox[235] = 8'he9;
        sbox[236] = 8'hce; sbox[237] = 8'h55; sbox[238] = 8'h28; sbox[239] = 8'hdf;
        
        sbox[240] = 8'h8c; sbox[241] = 8'ha1; sbox[242] = 8'h89; sbox[243] = 8'h0d;//row15 (F)
        sbox[244] = 8'hbf; sbox[245] = 8'he6; sbox[246] = 8'h42; sbox[247] = 8'h68;
        sbox[248] = 8'h41; sbox[249] = 8'h99; sbox[250] = 8'h2d; sbox[251] = 8'h0f;
        sbox[252] = 8'hb0; sbox[253] = 8'h54; sbox[254] = 8'hbb; sbox[255] = 8'h16;
    end

    function [7:0] SBox;
        input [7:0] byte_in;
        reg [3:0] row, col;
        begin
            row = byte_in[7:4];
            col = byte_in[3:0];
            SBox = sbox[{row, col}];
        end
    endfunction

    reg [31:0] temp;

    always @(*) begin
        for (i = 0; i < 4; i = i + 1) begin
            w[i] = key_in[(127 - i * 32) -: 32];
        end
        for (i = 4; i < 44; i = i + 1) begin
            temp = w[i-1];
            if (i % 4 == 0) begin
                temp = {temp[23:0], temp[31:24]}; 
                temp = {SBox(temp[31:24]), SBox(temp[23:16]), SBox(temp[15:8]), SBox(temp[7:0])}; 
                temp = temp ^ Rcon[(i/4)-1];
            end
            w[i] = w[i-4] ^ temp;
        end
        for (i = 0; i < 11; i = i + 1) begin
        
            round_keys[(1407 - i * 128) -: 128] = {w[i*4], w[i*4+1], w[i*4+2], w[i*4+3]};
        end
    end

endmodule
