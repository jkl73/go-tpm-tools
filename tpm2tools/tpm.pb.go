// Code generated by protoc-gen-go. DO NOT EDIT.
// source: tpm.proto

package tpm2tools

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type SealedBytes struct {
	Priv                 []byte   `protobuf:"bytes,1,opt,name=priv,proto3" json:"priv,omitempty"`
	Pub                  []byte   `protobuf:"bytes,2,opt,name=pub,proto3" json:"pub,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SealedBytes) Reset()         { *m = SealedBytes{} }
func (m *SealedBytes) String() string { return proto.CompactTextString(m) }
func (*SealedBytes) ProtoMessage()    {}
func (*SealedBytes) Descriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{0}
}

func (m *SealedBytes) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SealedBytes.Unmarshal(m, b)
}
func (m *SealedBytes) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SealedBytes.Marshal(b, m, deterministic)
}
func (m *SealedBytes) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SealedBytes.Merge(m, src)
}
func (m *SealedBytes) XXX_Size() int {
	return xxx_messageInfo_SealedBytes.Size(m)
}
func (m *SealedBytes) XXX_DiscardUnknown() {
	xxx_messageInfo_SealedBytes.DiscardUnknown(m)
}

var xxx_messageInfo_SealedBytes proto.InternalMessageInfo

func (m *SealedBytes) GetPriv() []byte {
	if m != nil {
		return m.Priv
	}
	return nil
}

func (m *SealedBytes) GetPub() []byte {
	if m != nil {
		return m.Pub
	}
	return nil
}

func init() {
	proto.RegisterType((*SealedBytes)(nil), "tpm2tools.SealedBytes")
}

func init() { proto.RegisterFile("tpm.proto", fileDescriptor_63ac7bc02f9d1279) }

var fileDescriptor_63ac7bc02f9d1279 = []byte{
	// 93 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x2c, 0x29, 0xc8, 0xd5,
	0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x02, 0x31, 0x8d, 0x4a, 0xf2, 0xf3, 0x73, 0x8a, 0x95, 0x8c,
	0xb9, 0xb8, 0x83, 0x53, 0x13, 0x73, 0x52, 0x53, 0x9c, 0x2a, 0x4b, 0x52, 0x8b, 0x85, 0x84, 0xb8,
	0x58, 0x0a, 0x8a, 0x32, 0xcb, 0x24, 0x18, 0x15, 0x18, 0x35, 0x78, 0x82, 0xc0, 0x6c, 0x21, 0x01,
	0x2e, 0xe6, 0x82, 0xd2, 0x24, 0x09, 0x26, 0xb0, 0x10, 0x88, 0x99, 0xc4, 0x06, 0x36, 0xc6, 0x18,
	0x10, 0x00, 0x00, 0xff, 0xff, 0x4f, 0x82, 0xc6, 0x33, 0x53, 0x00, 0x00, 0x00,
}