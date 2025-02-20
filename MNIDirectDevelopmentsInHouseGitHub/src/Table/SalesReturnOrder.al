tableextension 50202 MNISalesReturnOrder extends "Sales Header"
{
    fields
    {
        field(50200; ReturnReasonCode; Code[20])
        {
            Caption = 'Return Reason';
            TableRelation = "Return Reason"."Code";
            DataClassification = ToBeClassified;

            trigger OnValidate()
            begin
                if ReturnReasonCode = '' then
                    Error('The "Return Reason Code" must not be blank.');
            end;
        }
    }
}
