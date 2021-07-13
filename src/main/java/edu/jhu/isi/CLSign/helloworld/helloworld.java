package edu.jhu.isi.CLSign.helloworld;

import edu.jhu.isi.CLSign.CLSign;
import edu.jhu.isi.CLSign.keygen.KeyPair;
import edu.jhu.isi.CLSign.keygen.PublicKey;
import edu.jhu.isi.CLSign.keygen.SecretKey;
import edu.jhu.isi.CLSign.proof.Proof;
import edu.jhu.isi.CLSign.sign.Signature;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;

import java.util.ArrayList;
import java.util.List;


public class helloworld {

    public static void main(String[] args){
        System.out.println("=====Generating keys");
        final int messageSize = 1;
        final KeyPair keyPair = CLSign.keyGen(messageSize);
        final PublicKey pk = keyPair.getPk();
        final SecretKey sk = keyPair.getSk();


        System.out.println("Secret key size (Z):\t"+sk.getZ().size());
        System.out.println("Public key size (Z):\t"+pk.getZ().size());
        System.out.println("Public key size (W):\t"+pk.getW().size());
        System.out.println("Public key (X):\t"+pk.getX());
        System.out.println("Public key (Y):\t"+pk.getY());
        for (int i = 0; i < messageSize; i++) {
            System.out.println("Public key (Z):\t"+pk.getZ(i));
            System.out.println("Public key (W):\t"+pk.getW(i));
        }
        System.out.println("Public key (G1):\t"+pk.getPairing().getG1());
        System.out.println("Public key (G2):\t"+pk.getPairing().getG2());

        List<ZrElement> messages = new ArrayList<>();

        for (int i=0;i<messageSize;i++)
        {
            ZrElement mess = (ZrElement) keyPair.getPk().getPairing().getZr().newRandomElement().getImmutable();
            messages.add(mess);
        }

        System.out.println("=====Signing messages");
        Signature sigma = CLSign.sign(messages, keyPair);
        System.out.println("Sigma (a):\t"+sigma.getA());
        System.out.println("Sigma (b):\t"+sigma.getB());
        System.out.println("Sigma (c):\t"+sigma.getC());
        List<Element> Alist = sigma.getAList();
        System.out.println("Sigma (A):\t"+Alist.get(0));
        List<Element> Blist = sigma.getBList();
        System.out.println("Sigma (B):\t"+Blist.get(0));




        System.out.println("======Verifying signatures");
        boolean rtn=CLSign.verify(messages, sigma, keyPair.getPk());
        System.out.println("Check signature: "+rtn);

//        System.out.println("=====Blind Signing messages");
//        final Element commitment = CLSign.commit(messages, keyPair.getPk());
//        final Proof proof = CLSign.proofCommitment(commitment, messages, keyPair.getPk());
//        sigma = CLSign.signBlind(commitment, proof, keyPair);
//
//        System.out.println("======Verifying signatures");
//        rtn=CLSign.verify(messages, sigma, keyPair.getPk());
//        System.out.println("Check signature: "+rtn);


    }
}
