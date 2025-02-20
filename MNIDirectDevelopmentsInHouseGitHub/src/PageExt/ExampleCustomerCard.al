// pageextension 50201 "Customer Card Extension" extends "Customer Card"
// {
//     layout
//     {
//         addlast(General)
//         {
//             field(MNITestName; Rec.MNITestName)
//             {
//                 ApplicationArea = All;
//                 ShowMandatory = True;
//             }
//             field(MNIFeatureToggleTest; Rec.MNIFeatureToggleTest)
//             {
//                 ApplicationArea = All;
//                 Caption = 'Enable Feature Test';
//             }
//             field(MNIStatusTest; Rec.MNIStatusTest)
//             {
//                 Caption = 'Test Status';
//                 ApplicationArea = All;
//             }
//         }

//     }
//     trigger OnOpenPage()
//     begin
//         if Rec.MNITestName = '' then
//             Message('Please Fill in Test Name 1');
//     end;
// }

