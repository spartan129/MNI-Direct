pageextension 50202 MNISalesReturnOrderSubform extends "Sales Return Order"
{
    layout
    {
        addlast(General)
        {
            field(ReturnReasonCode; Rec.ReturnReasonCode)
            {
                ApplicationArea = All;
                Caption = 'Return Reason';
                ToolTip = 'Please fill in the return reason.';
                ShowMandatory = true;
            }
        }
    }

    trigger OnQueryClosePage(CloseAction: Action): Boolean
    begin
        // Allow the page to close if the document is empty (e.g., Customer Name is blank)
        if Rec."No." = '' then
            exit(true); // Allows closing if it's a blank document

        // Enforce the Return Reason Code requirement for non-empty documents
        if Rec.ReturnReasonCode = '' then begin
            Message('The "Return Reason Code" must be filled before you can close the document.');
            exit(false); // Prevents the page from closing
        end;

        exit(true); // Allows the page to close if all conditions are met
    end;


}
