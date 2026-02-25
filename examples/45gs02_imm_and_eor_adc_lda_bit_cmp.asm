; 45GS02 immediate opcode overrides for AND/EOR/ADC/LDA/BIT/CMP

	.cpu 45gs02
	.org $2000

start
	and #$11
	eor #$22
	adc #$33
	lda #$44
	bit #$55
	cmp #$66
	rts

	.end
