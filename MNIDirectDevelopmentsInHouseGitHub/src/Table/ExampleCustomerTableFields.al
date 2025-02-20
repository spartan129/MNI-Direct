// tableextension 50201 "MNICustomerTableFields" extends "Customer"
// {
//     fields
//     {
//         field(50200; MNIStatusTest; Enum "MNIStatusTest")
//         {
//             Caption = 'Status Test';
//             DataClassification = CustomerContent;
//         }
//         field(50201; MNITestName; Text[50])
//         {
//             Caption = 'Test Name1';
//         }
//         field(50202; MNIFeatureToggleTest; Boolean)
//         {
//             Caption = 'Enable Feature Test';
//             trigger OnValidate()
//             var
//                 Msg: Text;
//             begin
//                 if MNIFeatureToggleTest then
//                     Msg := 'Feature Enabled'
//                 else
//                     Msg := 'Feature Disabled';
//                 Message(Msg);
//             end;
//         }
//     }
// }